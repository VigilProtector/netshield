// Package main provides the NetShield API server.
//
//	@title                      NetShield API
//	@version                    1.0
//	@description                NetShield is a network threat and configuration assurance capability within the StratoWard family.
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

	"vigilprotector.io/netshield/internal/config"
	"vigilprotector.io/netshield/internal/http/handler"
	"vigilprotector.io/netshield/internal/http/router"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/netshield/internal/store"
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

	// Initialize services
	// Note: FlowSeeker client is nil for now, will be implemented in future phase
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
		nil, // FlowSeekerClient - will be wired in future
		logger,
	)

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
