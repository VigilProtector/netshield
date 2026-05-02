// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/vp-lib/correlation"
	vpauthn "vigilprotector.io/vp-lib/gin/middleware/authn"
	"vigilprotector.io/vp-lib/http/response"
	"vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// SensorHandler handles HTTP requests for sensor operations.
type SensorHandler struct {
	service service.SensorServicer
}

// SensorServicer defines the interface for sensor service operations.
// ADR: Consumer-defined interfaces - defined where consumed, not where implemented.
type SensorServicer interface {
	List(ctx context.Context, logger logr.Logger, subject *types.Subject, opts service.ListSensorsOptions) (*service.ListSensorsResult, error)
	Get(ctx context.Context, logger logr.Logger, subject *types.Subject, picketID string) (*models.Sensor, error)
}

// NewSensorHandler creates a new SensorHandler.
func NewSensorHandler(service SensorServicer) *SensorHandler {
	return &SensorHandler{
		service: service,
	}
}

// ListSensors lists all sensors with optional filtering.
// @Summary      List sensors
// @Description  Returns a paginated list of NetShield sensors (Pickets)
// @Tags         sensors
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        defconId query string false "Filter by Defcon ID"
// @Param        status query string false "Filter by status"
// @Param        health query string false "Filter by health"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.SensorAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/sensors [get]
func (h *SensorHandler) ListSensors(c *gin.Context) {
	// Get logger (ALWAYS first line)
	logger := logging.GetLogger(c)
	logger = correlation.GetLoggerWithCorrelationID(c, logger)

	// Ensure correlation ID
	ctx := correlation.Ensure(c.Request.Context())
	c.Request = c.Request.WithContext(ctx)

	// Extract subject
	subject, err := vpauthn.ExtractSubject(ctx)
	if err != nil {
		logger.Error(err, "failed to extract subject")
		response.SendError(c, http.StatusUnauthorized, "Authentication required", err.Error())
		return
	}

	// Parse query parameters
	var filter models.SensorFilter
	if defconID := c.Query("defconId"); defconID != "" {
		filter.DefconID = defconID
	}
	if status := c.Query("status"); status != "" {
		filter.Status = status
	}
	if health := c.Query("health"); health != "" {
		filter.Health = health
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := parseInt(l, 50); err == nil {
			limit = parsed
		}
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := parseInt(o, 0); err == nil {
			offset = parsed
		}
	}

	opts := service.ListSensorsOptions{
		Filter: models.SensorFilter{
			DefconID: filter.DefconID,
			Status:   filter.Status,
			Health:   filter.Health,
		},
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.List(ctx, logger, &subject, opts)
	if err != nil {
		logger.Error(err, "failed to list sensors")
		response.SendError(c, http.StatusInternalServerError, "Failed to list sensors", err.Error())
		return
	}

	// Success response
	logger.V(logging.LogLevelVerbose).Info("sensors listed successfully", "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Sensors listed successfully", result.Items)
}

// GetSensor returns a single sensor by Picket ID.
// @Summary      Get sensor
// @Description  Returns a single NetShield sensor by Picket ID
// @Tags         sensors
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        picketId path string true "Picket ID"
// @Success      200 {object} response.SuccessResponse{data=models.SensorAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/sensors/{picketId} [get]
func (h *SensorHandler) GetSensor(c *gin.Context) {
	// Get logger (ALWAYS first line)
	logger := logging.GetLogger(c)
	logger = correlation.GetLoggerWithCorrelationID(c, logger)

	// Ensure correlation ID
	ctx := correlation.Ensure(c.Request.Context())
	c.Request = c.Request.WithContext(ctx)

	// Extract subject
	subject, err := vpauthn.ExtractSubject(ctx)
	if err != nil {
		logger.Error(err, "failed to extract subject")
		response.SendError(c, http.StatusUnauthorized, "Authentication required", err.Error())
		return
	}

	// Get Picket ID from path
	picketID := c.Param("picketId")
	if picketID == "" {
		logger.V(logging.LogLevelInfo).Error(nil, "missing picketId parameter")
		response.SendError(c, http.StatusBadRequest, "picketId is required", nil)
		return
	}

	// Call service
	sensor, err := h.service.Get(ctx, logger, &subject, picketID)
	if err != nil {
		logger.Error(err, "failed to get sensor", "picketId", picketID)
		response.SendError(c, http.StatusInternalServerError, "Failed to get sensor", err.Error())
		return
	}

	// Success response
	logger.V(logging.LogLevelVerbose).Info("sensor retrieved successfully", "picketId", picketID)
	response.SendResponse(c, http.StatusOK, "Sensor retrieved successfully", sensor.ToAPI())
}

// parseInt is a helper function to parse integer query parameters.
func parseInt(s string, defaultValue int) (int, error) {
	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		return defaultValue, err
	}
	return val, nil
}
