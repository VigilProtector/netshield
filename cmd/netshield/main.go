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

	"vigilprotector.io/netshield/internal/config"
	"vigilprotector.io/netshield/internal/http/router"
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

	// Initialize router
	r := router.SetupRouter(logger)

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

func initializeLogger(cfg *config.Config) logr.Logger {
	return vplogging.NewLogger(cfg.Environment, cfg.LogEncoding, serviceName, cfg.LogLevel)
}
