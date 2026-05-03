// Package router provides HTTP routing for NetShield API.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/http/handler"
	"vigilprotector.io/vp-lib/authn"
	"vigilprotector.io/vp-lib/gin/middleware/vplogger"
)

// SetupRouter sets up the HTTP router for NetShield API.
func SetupRouter(
	logger logr.Logger,
	sensorHandler *handler.SensorHandler,
	ruleSetHandler *handler.RuleSetHandler,
	findingHandler *handler.FindingHandler,
	detectionHandler *handler.DetectionHandler,
) *gin.Engine {
	router := gin.New()

	// Platform middleware (MANDATORY)
	router.Use(gin.Recovery())
	router.Use(vplogger.Middleware(logger))

	// Health endpoints (MANDATORY, no auth)
	router.GET("/health", healthHandler)
	router.GET("/ready", readyHandler)

	// API routes
	v1 := router.Group("/netshield/v1")
	{
		v1.Use(authn.Middleware()) // Auth for all API routes

		// Sensor endpoints
		// NH-SM-001: Sensor-Management
		v1.GET("/sensors", sensorHandler.ListSensors)
		v1.GET("/sensors/:picketId", sensorHandler.GetSensor)

		// RuleSet endpoints
		// NH-RD-001..007: Regelset-Management-APIs
		v1.GET("/rulesets", ruleSetHandler.ListRuleSets)
		v1.GET("/rulesets/:id", ruleSetHandler.GetRuleSet)
		v1.POST("/rulesets", ruleSetHandler.CreateRuleSet)
		v1.PATCH("/rulesets/:id", ruleSetHandler.UpdateRuleSet)
		v1.DELETE("/rulesets/:id", ruleSetHandler.DeleteRuleSet)
		v1.POST("/rulesets/:id/enable", ruleSetHandler.EnableRuleSet)
		v1.POST("/rulesets/:id/disable", ruleSetHandler.DisableRuleSet)
		v1.GET("/rulesets/default", ruleSetHandler.GetDefaultRuleSet)
		v1.GET("/rulesets/:id/render", ruleSetHandler.RenderRuleSet)

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
		v1.GET("/sensors/:sensorId/detections", detectionHandler.GetDetectionsBySensor)
		v1.GET("/pickets/:picketId/detections", detectionHandler.GetDetectionsByPicket)
		v1.GET("/rulesets/:ruleSetId/detections", detectionHandler.GetDetectionsByRuleSet)
		v1.GET("/rules/:ruleId/detections", detectionHandler.GetDetectionsByRule)
		v1.GET("/detections/unprocessed", detectionHandler.GetUnprocessedDetections)
	}

	return router
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func readyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
