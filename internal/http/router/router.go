// Package router provides HTTP routing for NetShield API.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"vigilprotector.io/netshield/internal/http/handler"
	vpauthn "vigilprotector.io/vp-lib/gin/middleware/authn"
	"vigilprotector.io/vp-lib/gin/middleware/vplogger"
	_ "vigilprotector.io/netshield/docs"
)

// SetupRouter sets up the HTTP router for NetShield API.
func SetupRouter(logger logr.Logger) *gin.Engine {
	router := gin.New()

	// Platform middleware (MANDATORY)
	router.Use(gin.Recovery())
	router.Use(vplogger.VPLogger(logger))

	// Health endpoints (MANDATORY, no auth)
	router.GET("/health", healthHandler)
	router.GET("/ready", readyHandler)

	// Swagger (no auth)
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// API routes
	v1 := router.Group("/netshield/v1")
	{
		v1.Use(vpauthn.Middleware()) // Auth for all API routes

		// Sensor endpoints
		v1.GET("/sensors", handler.ListSensors)
		v1.GET("/sensors/:picketId", handler.GetSensor)

		// RuleSet endpoints
		v1.GET("/rulesets", handler.ListRuleSets)
		v1.GET("/rulesets/:id", handler.GetRuleSet)
		v1.POST("/rulesets", handler.CreateRuleSet)
		v1.PUT("/rulesets/:id", handler.UpdateRuleSet)
		v1.DELETE("/rulesets/:id", handler.DeleteRuleSet)
		v1.POST("/rulesets/:id/enable", handler.EnableRuleSet)
		v1.POST("/rulesets/:id/disable", handler.DisableRuleSet)

		// Finding endpoints
		v1.GET("/findings", handler.ListFindings)
		v1.GET("/findings/:findingId", handler.GetFinding)
		v1.PATCH("/findings/:findingId/lifecycle", handler.UpdateFindingLifecycle)
		v1.PATCH("/findings/:findingId/verification", handler.UpdateFindingVerification)

		// Detection endpoints
		v1.GET("/detections", handler.ListDetections)
		v1.GET("/detections/:detectionId", handler.GetDetection)
	}

	return router
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func readyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
