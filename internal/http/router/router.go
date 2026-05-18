// Package router provides HTTP routing for NetShield API.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/http/handler"
	"vigilprotector.io/vp-lib/authn/jwt"
	"vigilprotector.io/vp-lib/correlation"
	"vigilprotector.io/vp-lib/gin/middleware/vplogger"
)

// VP-2252 / PLATFORM-PATH-PREFIX: NetShield migrates its routes from the
// legacy /netshield/v1/... prefix to the platform-canonical
// /api/stratoward/v1/netshield/... prefix per the platform schema
// `/api/<capability>/<version>/<subcapability>` where the StratoWard
// suite is the capability and `netshield` is the sub-capability.
// The server registers both paths during the migration window so
// consumers can move at their own pace. Legacy responses carry
// X-Deprecated: 2026-05-11 so consumers see they're on the path
// scheduled for removal one sprint later.
const (
	apiPathPrefix          = "/api/stratoward/v1/netshield"
	legacyPathPrefix       = "/netshield/v1"
	legacyDeprecatedHeader = "X-Deprecated"
	legacyDeprecatedAt     = "2026-05-11"
)

// markLegacyDeprecated sets the X-Deprecated header on responses to
// legacy /netshield/v1/... requests. Clients that still hit the legacy
// path see this header in every response, so an out-of-band log scrape
// can identify consumers that need to migrate before the legacy
// prefix is removed.
//
// The header is set BOTH before calling the next handler and on the
// deferred path so an aborting middleware (authn rejection) still emits
// the deprecation marker — without the deferred Set, an unauthenticated
// caller would not see X-Deprecated in the 401 response.
func markLegacyDeprecated() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header(legacyDeprecatedHeader, legacyDeprecatedAt)
		c.Next()
		c.Header(legacyDeprecatedHeader, legacyDeprecatedAt)
	}
}

// registerRoutes wires the NetShield route table onto a gin RouterGroup.
// Called twice from SetupRouter: once for the canonical /api/-prefix
// path and once for the legacy /<cap>/v1 path during the migration
// window.
//
//nolint:funlen // route registration is dense by nature; splitting hides the table
func registerRoutes(
	v1 *gin.RouterGroup,
	sensorHandler *handler.SensorHandler,
	ruleSetHandler *handler.RuleSetHandler,
	findingHandler *handler.FindingHandler,
	detectionHandler *handler.DetectionHandler,
) {
	// Sensor endpoints
	// NH-SM-001: Sensor-Management
	v1.GET("/sensors", sensorHandler.ListSensors)
	v1.GET("/sensors/:picketId", sensorHandler.GetSensor)
	// NH-SM-006: Automatic Picket registration via webhook
	v1.POST("/sensors/webhook", sensorHandler.RegisterSensorViaWebhook)
	// NH-SM-007: Picket-Health-Tracking
	v1.PUT("/sensors/:picketId/lastseen", sensorHandler.UpdateLastSeen)

	// RuleSet endpoints
	// NH-RD-001..007: Regelset-Management-APIs
	v1.GET("/rulesets", ruleSetHandler.ListRuleSets)
	v1.POST("/rulesets", ruleSetHandler.CreateRuleSet)
	v1.GET("/rulesets/default", ruleSetHandler.GetDefaultRuleSet)
	v1.GET("/rulesets/:ruleSetId", ruleSetHandler.GetRuleSet)
	v1.PATCH("/rulesets/:ruleSetId", ruleSetHandler.UpdateRuleSet)
	v1.DELETE("/rulesets/:ruleSetId", ruleSetHandler.DeleteRuleSet)
	v1.POST("/rulesets/:ruleSetId/enable", ruleSetHandler.EnableRuleSet)
	v1.POST("/rulesets/:ruleSetId/disable", ruleSetHandler.DisableRuleSet)
	v1.GET("/rulesets/:ruleSetId/render", ruleSetHandler.RenderRuleSet)
	v1.GET("/rulesets/:ruleSetId/detections", detectionHandler.GetDetectionsByRuleSet)

	// Finding endpoints
	// VL-FC-001: Finding listing with filtering
	v1.GET("/findings", findingHandler.ListFindings)
	v1.GET("/findings/:findingId", findingHandler.GetFinding)
	v1.POST("/findings", findingHandler.CreateFinding)
	v1.PATCH("/findings/:findingId/lifecycle", findingHandler.UpdateFindingLifecycle)
	v1.PATCH("/findings/:findingId/verification", findingHandler.UpdateFindingVerification)
	v1.POST("/findings/mark-stale", findingHandler.MarkFindingsStale)

	// Finding endpoints by asset/defcon/type
	v1.GET("/assets/:assetId/findings", findingHandler.GetFindingsByAsset)
	v1.GET("/defcons/:defconId/findings", findingHandler.GetFindingsByDefcon)
	v1.GET("/findings/types/:findingType", findingHandler.GetFindingsByType)
	v1.GET("/findings/stale", findingHandler.GetStaleFindings)

	// Detection endpoints
	// NH-CC-001..004: Detection-Pipeline Core Components
	v1.GET("/detections", detectionHandler.ListDetections)
	v1.GET("/detections/:detectionId", detectionHandler.GetDetection)
	v1.POST("/detections", detectionHandler.CreateDetection)
	v1.POST("/detections/:detectionId/process", detectionHandler.ProcessDetection)
	v1.POST("/detections/:detectionId/mark-processed", detectionHandler.MarkAsProcessed)

	// Detection endpoints by sensor/picket/ruleSet/rule
	v1.GET("/sensors/:picketId/detections", detectionHandler.GetDetectionsBySensor)
	v1.GET("/pickets/:picketId/detections", detectionHandler.GetDetectionsByPicket)
	v1.GET("/rules/:ruleId/detections", detectionHandler.GetDetectionsByRule)
	v1.GET("/detections/unprocessed", detectionHandler.GetUnprocessedDetections)
}

// SetupRouter sets up the HTTP router for NetShield API.
func SetupRouter(
	logger logr.Logger,
	sensorHandler *handler.SensorHandler,
	ruleSetHandler *handler.RuleSetHandler,
	findingHandler *handler.FindingHandler,
	detectionHandler *handler.DetectionHandler,
	jwtValidator *jwt.Validator,
) *gin.Engine {
	router := gin.New()

	// Platform middleware (MANDATORY)
	router.Use(gin.Recovery())
	router.Use(correlation.Middleware())
	router.Use(vplogger.Middleware(logger))

	// Health endpoints (MANDATORY, no auth)
	router.GET("/health", healthHandler)
	router.GET("/ready", readyHandler)
	router.GET("/metrics", metricsHandler)

	// VP-2252 / PLATFORM-PATH-PREFIX: canonical /api/netshield/v1/...
	// route group. Both groups call registerRoutes with the same handler
	// pointers, so the route table stays single-sourced.
	apiV1 := router.Group(apiPathPrefix)
	apiV1.Use(jwt.Middleware(jwtValidator))
	registerRoutes(apiV1, sensorHandler, ruleSetHandler, findingHandler, detectionHandler)

	// Legacy /netshield/v1/... route group, kept for the migration
	// window. Responses carry X-Deprecated so consumers can detect they
	// are on the path scheduled for removal one sprint after this PR
	// lands.
	legacyV1 := router.Group(legacyPathPrefix)
	legacyV1.Use(markLegacyDeprecated())
	legacyV1.Use(jwt.Middleware(jwtValidator))
	registerRoutes(legacyV1, sensorHandler, ruleSetHandler, findingHandler, detectionHandler)

	return router
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func readyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

func metricsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "metrics not implemented"})
}
