// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/vp-lib/authn"
	"vigilprotector.io/vp-lib/authz"
	"vigilprotector.io/vp-lib/correlation"
	ginlogging "vigilprotector.io/vp-lib/gin/logging"
	"vigilprotector.io/vp-lib/gin/response"
	vplogging "vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// SensorHandler handles HTTP requests for sensor operations.
type SensorHandler struct {
	service service.SensorServiceInterface
}

// NewSensorHandler creates a new SensorHandler.
func NewSensorHandler(service service.SensorServiceInterface) *SensorHandler {
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
	logger := ginlogging.GetLogger(c)
	logger = ginlogging.GetLoggerWithCorrelationID(c, logger)

	// Ensure correlation ID
	ctx := correlation.Ensure(c.Request.Context())
	c.Request = c.Request.WithContext(ctx)

	// Extract subject
	subject, err := authn.ExtractSubject(ctx)
	if err != nil {
		logger.Error(err, "failed to extract subject")
		response.SendError(c, http.StatusUnauthorized, "authentication_required", "Authentication required", err.Error())

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.sensor.list"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "sensor",
		},
	)

	decision, authzErr := authz.Authorize(ctx, input)
	if authzErr != nil {
		logger.Error(authzErr, "authorization check failed")
		response.SendError(c, http.StatusInternalServerError, "authorization_failed", "Authorization check failed", authzErr.Error())

		return
	}

	if !decision.Allow {
		logger.V(vplogging.LogLevelInfo).Info("access denied", "reason", decision.Reason)
		response.SendError(c, http.StatusForbidden, "access_denied", "Access denied", decision.Reason)

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
		if parsed, err := parseAndValidateLimit(l, 50); err == nil {
			limit = parsed
		}
	}

	offset := 0

	if o := c.Query("offset"); o != "" {
		if parsed, err := parseAndValidateOffset(o, 0); err == nil {
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
	result, err := h.service.List(ctx, logger, subject, opts)
	if err != nil {
		logger.Error(err, "failed to list sensors")
		response.SendError(c, http.StatusInternalServerError, "list_sensors_failed", "Failed to list sensors", err.Error())

		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("sensors listed successfully", "count", len(result.Items))
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
	logger := ginlogging.GetLogger(c)
	logger = ginlogging.GetLoggerWithCorrelationID(c, logger)

	// Ensure correlation ID
	ctx := correlation.Ensure(c.Request.Context())
	c.Request = c.Request.WithContext(ctx)

	// Extract subject
	subject, err := authn.ExtractSubject(ctx)
	if err != nil {
		logger.Error(err, "failed to extract subject")
		response.SendError(c, http.StatusUnauthorized, "authentication_required", "Authentication required", err.Error())

		return
	}

	// Get Picket ID from path
	picketID := c.Param("picketId")
	if picketID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing picketId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "picketId is required", nil)

		return
	}

	// Call service
	sensor, err := h.service.Get(ctx, logger, subject, picketID)
	if err != nil {
		logger.Error(err, "failed to get sensor", "picketId", picketID)
		response.SendError(c, http.StatusInternalServerError, "get_sensor_failed", "Failed to get sensor", err.Error())

		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("sensor retrieved successfully", "picketId", picketID)
	response.SendResponse(c, http.StatusOK, "Sensor retrieved successfully", sensor.ToAPI())
}

// RegisterSensorViaWebhook registers a sensor via webhook endpoint.
// This implements the endpoint expected by stratoward-commander for NH-SM-006.
// @Summary      Register sensor via webhook
// @Description  Registers a new sensor through webhook call (stratoward-commander compatibility)
// @Tags         sensors
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body models.SensorAPI true "Sensor registration request"
// @Success      201 {object} response.SuccessResponse{data=models.SensorAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      403 {object} response.ErrorResponse
// @Failure      409 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/sensors/webhook [post]
func (h *SensorHandler) RegisterSensorViaWebhook(c *gin.Context) {
	// Get logger (ALWAYS first line)
	logger := ginlogging.GetLogger(c)
	logger = ginlogging.GetLoggerWithCorrelationID(c, logger)

	// Ensure correlation ID
	ctx := correlation.Ensure(c.Request.Context())
	c.Request = c.Request.WithContext(ctx)

	// Extract subject
	subject, err := authn.ExtractSubject(ctx)
	if err != nil {
		logger.Error(err, "failed to extract subject")
		response.SendError(c, http.StatusUnauthorized, "authentication_required", "Authentication required", err.Error())

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.sensor.create"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "sensor",
			ResourceRef:  "*",
		},
	)

	decision, authzErr := authz.Authorize(ctx, input)
	if authzErr != nil {
		logger.Error(authzErr, "authorization check failed")
		response.SendError(c, http.StatusInternalServerError, "authorization_failed", "Authorization check failed", authzErr.Error())

		return
	}

	if !decision.Allow {
		logger.V(vplogging.LogLevelInfo).Info("access denied", "reason", decision.Reason)
		response.SendError(c, http.StatusForbidden, "access_denied", "Access denied", decision.Reason)

		return
	}

	// Parse request body
	var sensorAPI models.SensorAPI
	if err := c.ShouldBindJSON(&sensorAPI); err != nil {
		logger.Error(err, "failed to bind request body")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid request body", err.Error())

		return
	}

	// Convert API model to domain model
	sensor, err := sensorAPI.FromAPI()
	if err != nil {
		logger.Error(err, "failed to convert sensor from API model")
		response.SendError(c, http.StatusBadRequest, "invalid_sensor_data", "Failed to convert sensor data", err.Error())

		return
	}

	// Call service
	result, err := h.service.Register(ctx, logger, subject, sensor)
	if err != nil {
		logger.Error(err, "failed to register sensor")
		response.SendError(c, http.StatusInternalServerError, "register_sensor_failed", "Failed to register sensor", err.Error())

		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("sensor registered successfully via webhook", "picketId", result.PicketID)
	response.SendResponse(c, http.StatusCreated, "Sensor registered successfully", result.ToAPI())
}

// UpdateLastSeen updates the last seen timestamp for a sensor.
// This implements the endpoint expected by stratoward-commander for NH-SM-007.
// @Summary      Update sensor last seen
// @Description  Updates the last seen timestamp for a sensor (Picket-Health-Tracking)
// @Tags         sensors
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        picketId path string true "Picket ID"
// @Success      200 {object} response.SuccessResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      403 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/sensors/{picketId}/lastseen [put]
func (h *SensorHandler) UpdateLastSeen(c *gin.Context) {
	// Get logger (ALWAYS first line)
	logger := ginlogging.GetLogger(c)
	logger = ginlogging.GetLoggerWithCorrelationID(c, logger)

	// Ensure correlation ID
	ctx := correlation.Ensure(c.Request.Context())
	c.Request = c.Request.WithContext(ctx)

	// Extract subject
	subject, err := authn.ExtractSubject(ctx)
	if err != nil {
		logger.Error(err, "failed to extract subject")
		response.SendError(c, http.StatusUnauthorized, "authentication_required", "Authentication required", err.Error())

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.sensor.update"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "sensor",
			ResourceRef:  "*",
		},
	)

	decision, authzErr := authz.Authorize(ctx, input)
	if authzErr != nil {
		logger.Error(authzErr, "authorization check failed")
		response.SendError(c, http.StatusInternalServerError, "authorization_failed", "Authorization check failed", authzErr.Error())

		return
	}

	if !decision.Allow {
		logger.V(vplogging.LogLevelInfo).Info("access denied", "reason", decision.Reason)
		response.SendError(c, http.StatusForbidden, "access_denied", "Access denied", decision.Reason)

		return
	}

	// Get picketId from path
	picketID := c.Param("picketId")
	if picketID == "" {
		logger.Error(nil, "picketId path parameter is required")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "picketId path parameter is required", "")

		return
	}

	// Call service
	_, err = h.service.UpdateLastSeen(ctx, logger, subject, picketID)
	if err != nil {
		logger.Error(err, "failed to update last seen")
		response.SendError(c, http.StatusInternalServerError, "update_lastseen_failed", "Failed to update last seen", err.Error())

		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("sensor last seen updated successfully", "picketId", picketID)
	response.SendResponse(c, http.StatusOK, "Sensor last seen updated successfully", nil)
}
