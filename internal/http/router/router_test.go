// Package router provides HTTP routing for NetShield API.
package router

import (
	"net/http"
	"net/http/httptest"
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

	// VP-2252 / PLATFORM-PATH-PREFIX: NetShield serves both the
	// canonical /api/stratoward/v1/netshield/... prefix and the legacy
	// /netshield/v1/... prefix during the migration window. Every
	// API path must be reachable under both groups.
	expectedPaths := []string{
		"/api/stratoward/v1/netshield/sensors",
		"/api/stratoward/v1/netshield/rulesets",
		"/api/stratoward/v1/netshield/findings",
		"/api/stratoward/v1/netshield/detections",
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

// TestMarkLegacyDeprecated_SetsHeader pins the VP-2252 migration
// contract at the middleware level: the markLegacyDeprecated handler
// must emit X-Deprecated on every response, regardless of whether the
// downstream chain reached the actual route handler. The router-level
// integration is harder to test in isolation because NetShield's
// SetupRouter does not register correlation.Middleware (pre-existing
// gap, separate concern), so we exercise the middleware directly.
func TestMarkLegacyDeprecated_SetsHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(markLegacyDeprecated())
	engine.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, legacyDeprecatedAt, rec.Header().Get(legacyDeprecatedHeader),
		"markLegacyDeprecated must write the X-Deprecated header on every response")
}

// TestMarkLegacyDeprecated_HeaderSurvivesAbort covers the more
// important property: even when a downstream middleware aborts the
// request (e.g. authn rejects an unauthenticated request), the
// X-Deprecated header MUST still appear on the response. Without that
// property a 401 from the legacy path would be indistinguishable from
// a 401 from the canonical path, defeating the migration tracking.
func TestMarkLegacyDeprecated_HeaderSurvivesAbort(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(markLegacyDeprecated())
	engine.Use(func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no token"})
	})
	engine.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "should not reach here") })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, legacyDeprecatedAt, rec.Header().Get(legacyDeprecatedHeader),
		"X-Deprecated must survive aborts from downstream middleware")
}
