// Package main provides the NetShield API server.
//
//	@title                      NetShield API
//	@version                    1.0
//	@description                NetShield provides network threat and configuration assurance.
//
//	@contact.name               VigilProtector Platform Team
//	@contact.url                https://docs.vigilprotector.io
//	@contact.email              platform@vigilprotector.io
//
//	@license.name               Proprietary
//	@license.url                https://vigilprotector.io/license
//
//	@host                       localhost:8900
//	@BasePath                   /
//	@schemes                    http https
//
//	@securityDefinitions.apikey BearerAuth
//	@in                         header
//	@name                       Authorization
//	@description                Enter your Bearer token in the format: Bearer {token}
//
//	@tag.name                   sensors
//	@tag.description            Operations on NetShield Sensors (Pickets)
//
//	@tag.name                   rulesets
//	@tag.description            Operations on RuleSets
//
//	@tag.name                   findings
//	@tag.description            Operations on Security Findings
//
//	@tag.name                   detections
//	@tag.description            Operations on Detections
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"vigilprotector.io/netshield/internal/client"
	"vigilprotector.io/netshield/internal/config"
	"vigilprotector.io/netshield/internal/http/handler"
	"vigilprotector.io/netshield/internal/http/router"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/netshield/internal/store"
	"vigilprotector.io/vp-lib/findings/pullcursor"
	vplogging "vigilprotector.io/vp-lib/logging"
)

var version = "development" // Set at build time

const serviceName = "netshield"

func main() {
	err := runServer()
	if err != nil {
		panic(err)
	}
}

//nolint:funlen // Main server function with comprehensive setup logic including FlowSeeker wiring
func runServer() error {
	cfg, err := config.LoadConfig()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := initializeLogger(cfg)

	logger.V(vplogging.LogLevelInfo).Info("Starting NetShield API server", "version", version)

	// Initialize MongoDB client
	mongoClient, err := initializeMongoDB(cfg)
	if err != nil {
		logger.Error(err, "failed to initialize MongoDB")
		os.Exit(1)
	}

	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			logger.Error(err, "failed to disconnect MongoDB")
		}
	}()

	// Initialize stores
	db := mongoClient.Database(cfg.Database.Name)
	sensorStore := store.NewSensorStore(
		db.Collection("sensors"),
		logger,
	)
	ruleSetStore := store.NewRuleSetStore(
		db.Collection("rulesets"),
		logger,
	)
	findingStore := store.NewFindingStore(
		db.Collection("findings"),
		logger,
	)
	detectionStore := store.NewDetectionStore(
		db.Collection("detections"),
		logger,
	)

	// Ensure indexes for each store
	if err := sensorStore.EnsureIndex(context.Background()); err != nil {
		logger.Error(err, "failed to ensure sensor indexes")
		os.Exit(1)
	}

	if err := ruleSetStore.EnsureIndex(context.Background()); err != nil {
		logger.Error(err, "failed to ensure ruleset indexes")
		os.Exit(1)
	}

	if err := findingStore.EnsureIndex(context.Background()); err != nil {
		logger.Error(err, "failed to ensure finding indexes")
		os.Exit(1)
	}

	if err := detectionStore.EnsureIndex(context.Background()); err != nil {
		logger.Error(err, "failed to ensure detection indexes")
		os.Exit(1)
	}

	// Initialize FlowSeeker subscription client (NH-LM-005)
	var flowSeekerClient *pullcursor.SubscriptionClient

	var flowSeekerConsumer *service.FlowSeekerConsumer

	if cfg.FlowSeeker.BaseURL != "" {
		httpClient := &http.Client{
			Timeout: 30 * time.Second,
		}

		cursorStore := &pullcursor.InMemoryCursorStore{}

		subscriptionConfig := pullcursor.SubscriptionClientConfig{
			BaseURL:      cfg.FlowSeeker.BaseURL,
			HTTPClient:   httpClient,
			CursorStore:  cursorStore,
			PollInterval: cfg.FlowSeeker.PollInterval,
			BatchSize:    cfg.FlowSeeker.BatchSize,
		}

		var err error

		flowSeekerClient, err = pullcursor.NewSubscriptionClient(subscriptionConfig)
		if err != nil {
			logger.Error(err, "failed to create FlowSeeker subscription client")
			os.Exit(1)
		}

		logger.V(vplogging.LogLevelInfo).Info("FlowSeeker subscription client configured",
			"baseURL", cfg.FlowSeeker.BaseURL,
			"pollInterval", cfg.FlowSeeker.PollInterval,
			"batchSize", cfg.FlowSeeker.BatchSize)
	}

	// Initialize FlowSeeker HTTP client for correlation (NH-CC-001..004)
	var flowSeekerCorrelationClient service.FlowSeekerClient

	if cfg.FlowSeeker.BaseURL != "" {
		correlationHTTPClient := &http.Client{
			Timeout: 30 * time.Second,
		}
		flowSeekerCorrelationClient = service.NewFlowSeekerHTTPClient(
			cfg.FlowSeeker.BaseURL,
			correlationHTTPClient,
			logger,
		)
	}

	// Initialize Cross-BC Query Clients for NH-CC-005
	// Aegis Client for Asset-Identity and Criticality
	var aegisClient *client.AegisClient
	if cfg.Aegis.BaseURL != "" { //nolint:wsl // Client initialization requires multiple assignments for HTTP client and service client
		aegisHTTPClient := client.NewHTTPClientWithTimeout(cfg.Aegis.Timeout, logger)
		aegisClient = client.NewAegisClient(cfg.Aegis.BaseURL, aegisHTTPClient, logger)
	}
	if aegisClient != nil { //nolint:wsl // Configuration logging must follow client initialization immediately
		logger.V(vplogging.LogLevelInfo).Info("Aegis client configured",
			"baseURL", cfg.Aegis.BaseURL,
			"timeout", cfg.Aegis.Timeout)
	}

	// NetSentinel Client for Device-Facts and Flow-Metrics
	var netSentinelClient *client.NetSentinelClient
	if cfg.NetSentinel.BaseURL != "" { //nolint:wsl // Client initialization requires multiple assignments for HTTP client and service client
		netSentinelHTTPClient := client.NewHTTPClientWithTimeout(cfg.NetSentinel.Timeout, logger)
		netSentinelClient = client.NewNetSentinelClient(
			cfg.NetSentinel.BaseURL,
			netSentinelHTTPClient,
			logger,
		)
	}
	if netSentinelClient != nil { //nolint:wsl // Configuration logging must follow client initialization immediately
		logger.V(vplogging.LogLevelInfo).Info("NetSentinel client configured",
			"baseURL", cfg.NetSentinel.BaseURL,
			"timeout", cfg.NetSentinel.Timeout)
	}

	// NetAtlas Client for Zone and Topology
	var netAtlasClient *client.NetAtlasClient
	if cfg.NetAtlas.BaseURL != "" { //nolint:wsl // Client initialization requires multiple assignments for HTTP client and service client
		netAtlasHTTPClient := client.NewHTTPClientWithTimeout(cfg.NetAtlas.Timeout, logger)
		netAtlasClient = client.NewNetAtlasClient(cfg.NetAtlas.BaseURL, netAtlasHTTPClient, logger)
	}
	if netAtlasClient != nil { //nolint:wsl // Configuration logging must follow client initialization immediately
		logger.V(vplogging.LogLevelInfo).Info("NetAtlas client configured",
			"baseURL", cfg.NetAtlas.BaseURL,
			"timeout", cfg.NetAtlas.Timeout)
	}

	// Initialize services
	// Note: FlowSeekerClient for detectionService (correlation) is separate from
	// FlowSeekerConsumer (subscription). FlowSeekerConsumer handles finding subscription
	// (NH-LM-005/006), while FlowSeekerClient handles correlation (NH-CC-001..004).
	sensorService := service.NewSensorService(
		sensorStore,
		nil, // VigilNetClient - will be wired in future
		logger,
	)
	ruleSetService := service.NewRuleSetService(
		ruleSetStore,
		nil, // RuleStore - will be wired in future
		logger,
	)
	findingService := service.NewFindingService(
		findingStore,
		logger,
	)
	detectionService := service.NewDetectionService(
		detectionStore,
		findingStore,
		flowSeekerCorrelationClient, // FlowSeekerClient for correlation (NH-CC-005)
		logger,
	)

	// Initialize Lateral Movement Detector (NH-LM-001..007)
	lateralMovementConfig := service.DefaultLateralMovementConfig()
	lateralMovementDetector := service.NewLateralMovementDetector(
		lateralMovementConfig,
		logger,
	)

	// Initialize and start FlowSeekerConsumer if subscription client is configured
	// Implements NH-LM-005: FlowSeeker-Finding-Subscription via VL-FC-002
	// Implements NH-LM-006: Event-driven Enrichment-Pipeline
	// Implements NH-LM-007: Emission network.lateral_movement_suspected
	// Implements NH-CC-005: Cross-BC Queries (Aegis, NetSentinel, NetAtlas)
	if flowSeekerClient != nil {
		// Create adapter wrappers for cross-BC clients
		aegisAdapter := service.NewAegisClientAdapter(aegisClient)
		netSentinelAdapter := service.NewNetSentinelClientAdapter(netSentinelClient)
		netAtlasAdapter := service.NewNetAtlasClientAdapter(netAtlasClient)

		flowSeekerConsumer = service.NewFlowSeekerConsumer(
			flowSeekerClient,
			detectionService,
			findingService,
			flowSeekerCorrelationClient, // FlowSeekerClient for flow context (NH-CC-005, NH-LM-006)
			lateralMovementDetector,     // LateralMovementDetector for NH-LM-001..007
			lateralMovementConfig,       // Configuration for lateral movement detection
			aegisAdapter,                // AegisClientAdapter for Asset-Identity/Criticality (NH-CC-005)
			netSentinelAdapter,          // NetSentinelClientAdapter for Flow-Metrics (NH-CC-005)
			netAtlasAdapter,             // NetAtlasClientAdapter for Zone/Topology (NH-CC-005)
			logger,
			cfg.FlowSeeker.PollInterval,
		)
	}

	// Initialize handlers
	sensorHandler := handler.NewSensorHandler(sensorService)
	ruleSetHandler := handler.NewRuleSetHandler(ruleSetService)
	findingHandler := handler.NewFindingHandler(findingService)
	detectionHandler := handler.NewDetectionHandler(detectionService)

	// Initialize router
	r := router.SetupRouter(
		logger,
		sensorHandler,
		ruleSetHandler,
		findingHandler,
		detectionHandler,
	)

	srv := &http.Server{
		Addr:              ":" + cfg.Server.Port,
		Handler:           r,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// Start FlowSeekerConsumer if configured (NH-LM-005)
	var flowSeekerCtx context.Context

	var flowSeekerCancel context.CancelFunc

	if flowSeekerConsumer != nil {
		flowSeekerCtx, flowSeekerCancel = context.WithCancel(context.Background())
		go func() {
			logger.V(vplogging.LogLevelInfo).Info("starting FlowSeeker consumer")

			if err := flowSeekerConsumer.Start(flowSeekerCtx); err != nil {
				logger.Error(err, "FlowSeeker consumer failed")
			}
		}()
	}

	go func() {
		logger.V(vplogging.LogLevelInfo).Info("starting http server", "port", cfg.Server.Port)

		errOnServe := srv.ListenAndServe()
		if errOnServe != nil && !errors.Is(errOnServe, http.ErrServerClosed) {
			logger.Error(errOnServe, "failed to start http server")
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.V(vplogging.LogLevelInfo).Info("shutting down server")

	// Cancel FlowSeekerConsumer context
	if flowSeekerCancel != nil {
		flowSeekerCancel()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	err = srv.Shutdown(shutdownCtx)
	if err != nil {
		logger.Error(err, "server forced to shutdown")
	}

	logger.V(vplogging.LogLevelInfo).Info("Server exited gracefully")

	return nil
}

// initializeMongoDB initializes the MongoDB client.
func initializeMongoDB(cfg *config.Config) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Database.Timeout)
	defer cancel()

	clientOpts := options.Client().ApplyURI(cfg.Database.URI)

	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Verify the connection
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	return client, nil
}

// initializeLogger creates a new logger instance.
func initializeLogger(cfg *config.Config) logr.Logger {
	return vplogging.NewLogger(cfg.Environment, cfg.LogEncoding, serviceName, cfg.LogLevel)
}
