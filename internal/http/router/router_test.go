// Package router provides HTTP routing for NetShield API.
package router

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"vigilprotector.io/netshield/internal/http/handler"
	"vigilprotector.io/vp-lib/logging"
)

// TestSetupRouter tests the SetupRouter function.
func TestSetupRouter(t *testing.T) {
	// Create a logger
	logger := logging.NewLogger("development", "console", "netshield-test", 0)

	// Create mock handlers with nil services
	// SetupRouter should handle nil services gracefully
	sensorHandler := handler.NewSensorHandler(nil)
	ruleSetHandler := handler.NewRuleSetHandler(nil)
	findingHandler := handler.NewFindingHandler(nil)
	detectionHandler := handler.NewDetectionHandler(nil)

	// Setup router
	router := SetupRouter(
		logger,
		sensorHandler,
		ruleSetHandler,
		findingHandler,
		detectionHandler,
	)

	// Verify router is not nil
	assert.NotNil(t, router)
	assert.IsType(t, &gin.Engine{}, router)
}

// TestRouterRoutes tests that all expected routes are registered.
func TestRouterRoutes(t *testing.T) {
	// Create a logger
	logger := logging.NewLogger("development", "console", "netshield-test", 0)

	// Create mock handlers
	sensorHandler := handler.NewSensorHandler(nil)
	ruleSetHandler := handler.NewRuleSetHandler(nil)
	findingHandler := handler.NewFindingHandler(nil)
	detectionHandler := handler.NewDetectionHandler(nil)

	// Setup router
	router := SetupRouter(
		logger,
		sensorHandler,
		ruleSetHandler,
		findingHandler,
		detectionHandler,
	)

	// Get all routes
	routes := router.Routes()

	// Define expected routes (at minimum these should exist)
	expectedPaths := []string{
		"/netshield/v1/sensors",
		"/netshield/v1/rulesets",
		"/netshield/v1/findings",
		"/netshield/v1/detections",
		"/health",
		"/ready",
		"/metrics",
	}

	// Create a map of registered paths for quick lookup
	registeredPaths := make(map[string]bool)
	for _, route := range routes {
		registeredPaths[route.Path] = true
	}

	// Check that expected paths are registered
	for _, expectedPath := range expectedPaths {
		if !registeredPaths[expectedPath] {
			t.Errorf("Expected route %s not found in registered routes", expectedPath)
		}
	}
}
