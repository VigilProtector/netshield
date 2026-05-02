// Package router provides HTTP routing for NetShield API.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"

	"vigilprotector.io/vp-lib/authn"
	"vigilprotector.io/vp-lib/gin/middleware/vplogger"
)

// SetupRouter sets up the HTTP router for NetShield API.
func SetupRouter(logger logr.Logger) *gin.Engine {
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
		// Note: Handlers need to be wired up with service in main.go
		// v1.GET("/sensors", sensorHandler.ListSensors)
		// v1.GET("/sensors/:picketId", sensorHandler.GetSensor)

		// RuleSet endpoints (TODO: implement)
		// v1.GET("/rulesets", handler.ListRuleSets)
		// v1.GET("/rulesets/:id", handler.GetRuleSet)
		// v1.POST("/rulesets", handler.CreateRuleSet)
		// v1.PUT("/rulesets/:id", handler.UpdateRuleSet)
		// v1.DELETE("/rulesets/:id", handler.DeleteRuleSet)
		// v1.POST("/rulesets/:id/enable", handler.EnableRuleSet)
		// v1.POST("/rulesets/:id/disable", handler.DisableRuleSet)

		// Finding endpoints (TODO: implement)
		// v1.GET("/findings", handler.ListFindings)
		// v1.GET("/findings/:findingId", handler.GetFinding)
		// v1.PATCH("/findings/:findingId/lifecycle", handler.UpdateFindingLifecycle)
		// v1.PATCH("/findings/:findingId/verification", handler.UpdateFindingVerification)

		// Detection endpoints (TODO: implement)
		// v1.GET("/detections", handler.ListDetections)
		// v1.GET("/detections/:detectionId", handler.GetDetection)
	}

	return router
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func readyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
