// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"errors"
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

// DetectionHandler handles HTTP requests for detection operations.
type DetectionHandler struct {
	service service.DetectionServiceInterface
}

// NewDetectionHandler creates a new DetectionHandler.
func NewDetectionHandler(service service.DetectionServiceInterface) *DetectionHandler {
	return &DetectionHandler{
		service: service,
	}
}

// ListDetections lists all detections with optional filtering.
// @Summary      List detections
// @Description  Returns a paginated list of NetShield detections
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        sensorId query string false "Filter by sensor ID"
// @Param        picketId query string false "Filter by Picket ID"
// @Param        ruleSetId query string false "Filter by rule set ID"
// @Param        ruleId query string false "Filter by rule ID"
// @Param        eventType query string false "Filter by event type"
// @Param        severity query string false "Filter by severity"
// @Param        startTime query string false "Filter by start time (RFC3339)"
// @Param        endTime query string false "Filter by end time (RFC3339)"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.DetectionAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/detections [get]
func (h *DetectionHandler) ListDetections(c *gin.Context) {
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
		types.Action("netshield.detection.list"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
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
	var filter models.DetectionFilter
	if sensorID := c.Query("sensorId"); sensorID != "" {
		filter.SensorID = sensorID
	}

	if picketID := c.Query("picketId"); picketID != "" {
		filter.PicketID = picketID
	}

	if ruleSetID := c.Query("ruleSetId"); ruleSetID != "" {
		filter.RuleSetID = ruleSetID
	}

	if ruleID := c.Query("ruleId"); ruleID != "" {
		filter.RuleID = ruleID
	}

	if eventType := c.Query("eventType"); eventType != "" {
		filter.EventType = eventType
	}

	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}

	if startTime := c.Query("startTime"); startTime != "" {
		filter.StartTime = startTime
	}

	if endTime := c.Query("endTime"); endTime != "" {
		filter.EndTime = endTime
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

	opts := models.ListDetectionsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.List(ctx, logger, subject, opts)
	if err != nil {
		logger.Error(err, "failed to list detections")
		response.SendError(c, http.StatusInternalServerError, "list_detections_failed", "Failed to list detections", err.Error())

		return
	}

	// Convert to API models
	apiDetections := make([]*models.DetectionAPI, len(result.Items))
	for i, d := range result.Items {
		apiDetections[i] = d.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detections listed successfully", "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Detections listed successfully", apiDetections)
}

// GetDetection returns a single detection by detection ID.
// @Summary      Get detection
// @Description  Returns a single NetShield detection by detection ID
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        detectionId path string true "Detection ID"
// @Success      200 {object} response.SuccessResponse{data=models.DetectionAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/detections/{detectionId} [get]
func (h *DetectionHandler) GetDetection(c *gin.Context) {
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

	// Get detection ID from path
	detectionID := c.Param("detectionId")
	if detectionID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing detectionId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "detectionId is required", nil)

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.detection.read"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  detectionID,
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

	// Call service
	detection, err := h.service.Get(ctx, logger, subject, detectionID)
	if err != nil {
		logger.Error(err, "failed to get detection", "detectionId", detectionID)
		response.SendError(c, http.StatusInternalServerError, "get_detection_failed", "Failed to get detection", err.Error())

		return
	}

	if detection == nil {
		response.SendError(c, http.StatusNotFound, "detection_not_found", "Detection not found", nil)
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detection retrieved successfully", "detectionId", detectionID)
	response.SendResponse(c, http.StatusOK, "Detection retrieved successfully", detection.ToAPI())
}

// CreateDetection creates a new detection.
// @Summary      Create detection
// @Description  Creates a new NetShield detection from SuricataGate
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body models.DetectionAPI true "Detection creation request"
// @Success      201 {object} response.SuccessResponse{data=models.DetectionAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      409 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/detections [post]
func (h *DetectionHandler) CreateDetection(c *gin.Context) {
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
		types.Action("netshield.detection.create"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
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
	var req models.DetectionAPI
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error(err, "failed to parse request body")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid request body", err.Error())

		return
	}

	// Convert to internal model
	detection, err := req.FromAPI()
	if err != nil {
		logger.Error(err, "failed to convert from API model")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid detection data", err.Error())

		return
	}

	// Call service
	detection, err = h.service.Create(ctx, logger, subject, detection)
	if err != nil {
		logger.Error(err, "failed to create detection")

		// Handle specific errors
		if errors.Is(err, service.ErrDetectionAlreadyExists) {
			response.SendError(c, http.StatusConflict, "detection_already_exists", "Detection already exists", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "create_detection_failed", "Failed to create detection", err.Error())

		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detection created successfully", "detectionId", detection.DetectionID)
	response.SendResponse(c, http.StatusCreated, "Detection created successfully", detection.ToAPI())
}

// ProcessDetection processes a detection and creates a finding if appropriate.
// @Summary      Process detection
// @Description  Processes a detection and creates a finding if appropriate
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        detectionId path string true "Detection ID"
// @Success      200 {object} response.SuccessResponse{data=models.FindingAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/detections/{detectionId}/process [post]
func (h *DetectionHandler) ProcessDetection(c *gin.Context) {
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

	// Get detection ID from path
	detectionID := c.Param("detectionId")
	if detectionID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing detectionId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "detectionId is required", nil)

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.detection.process"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  detectionID,
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

	// Call service
	finding, err := h.service.ProcessDetection(ctx, logger, subject, detectionID)
	if err != nil {
		logger.Error(err, "failed to process detection", "detectionId", detectionID)

		// Handle specific errors
		if errors.Is(err, service.ErrDetectionNotFound) {
			response.SendError(c, http.StatusNotFound, "detection_not_found", "Detection not found", err.Error())
			return
		}

		if errors.Is(err, service.ErrDetectionAlreadyProcessed) {
			response.SendError(c, http.StatusBadRequest, "already_processed", "Detection already processed", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "process_detection_failed", "Failed to process detection", err.Error())

		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detection processed successfully", "detectionId", detectionID)
	response.SendResponse(c, http.StatusOK, "Detection processed successfully", finding.ToAPI())
}

// MarkAsProcessed marks a detection as processed.
// @Summary      Mark detection as processed
// @Description  Marks a detection as processed
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        detectionId path string true "Detection ID"
// @Success      200 {object} response.SuccessResponse{data=string}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/detections/{detectionId}/mark-processed [post]
func (h *DetectionHandler) MarkAsProcessed(c *gin.Context) {
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

	// Get detection ID from path
	detectionID := c.Param("detectionId")
	if detectionID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing detectionId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "detectionId is required", nil)

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.detection.update"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  detectionID,
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

	// Call service
	err = h.service.MarkAsProcessed(ctx, logger, subject, detectionID)
	if err != nil {
		logger.Error(err, "failed to mark detection as processed", "detectionId", detectionID)

		// Handle specific errors
		if errors.Is(err, service.ErrDetectionNotFound) {
			response.SendError(c, http.StatusNotFound, "detection_not_found", "Detection not found", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "mark_processed_failed", "Failed to mark detection as processed", err.Error())

		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detection marked as processed successfully", "detectionId", detectionID)
	response.SendResponse(c, http.StatusOK, "Detection marked as processed successfully", nil)
}

// GetDetectionsBySensor returns detections for a specific sensor.
// @Summary      Get detections by sensor
// @Description  Returns detections for a specific sensor
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        sensorId path string true "Sensor ID"
// @Param        picketId query string false "Filter by Picket ID"
// @Param        ruleSetId query string false "Filter by rule set ID"
// @Param        ruleId query string false "Filter by rule ID"
// @Param        eventType query string false "Filter by event type"
// @Param        severity query string false "Filter by severity"
// @Param        startTime query string false "Filter by start time (RFC3339)"
// @Param        endTime query string false "Filter by end time (RFC3339)"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.DetectionAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/sensors/{picketId}/detections [get]
func (h *DetectionHandler) GetDetectionsBySensor(c *gin.Context) {
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

	// Get picket ID from path (sensors are identified by Picket ID)
	sensorID := c.Param("picketId")
	if sensorID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing picketId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "picketId is required", nil)

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.detection.list"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  sensorID,
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
	var filter models.DetectionFilter
	if picketID := c.Query("picketId"); picketID != "" {
		filter.PicketID = picketID
	}

	if ruleSetID := c.Query("ruleSetId"); ruleSetID != "" {
		filter.RuleSetID = ruleSetID
	}

	if ruleID := c.Query("ruleId"); ruleID != "" {
		filter.RuleID = ruleID
	}

	if eventType := c.Query("eventType"); eventType != "" {
		filter.EventType = eventType
	}

	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}

	if startTime := c.Query("startTime"); startTime != "" {
		filter.StartTime = startTime
	}

	if endTime := c.Query("endTime"); endTime != "" {
		filter.EndTime = endTime
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

	opts := models.ListDetectionsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetBySensorID(ctx, logger, subject, sensorID, opts)
	if err != nil {
		logger.Error(err, "failed to get detections by sensor", "sensorId", sensorID)
		response.SendError(c, http.StatusInternalServerError, "get_detections_by_sensor_failed", "Failed to get detections by sensor", err.Error())

		return
	}

	// Convert to API models
	apiDetections := make([]*models.DetectionAPI, len(result.Items))
	for i, d := range result.Items {
		apiDetections[i] = d.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detections by sensor retrieved successfully", "sensorId", sensorID, "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Detections by sensor retrieved successfully", apiDetections)
}

// GetDetectionsByPicket returns detections for a specific Picket.
// @Summary      Get detections by Picket
// @Description  Returns detections for a specific Picket
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        picketId path string true "Picket ID"
// @Param        sensorId query string false "Filter by sensor ID"
// @Param        ruleSetId query string false "Filter by rule set ID"
// @Param        ruleId query string false "Filter by rule ID"
// @Param        eventType query string false "Filter by event type"
// @Param        severity query string false "Filter by severity"
// @Param        startTime query string false "Filter by start time (RFC3339)"
// @Param        endTime query string false "Filter by end time (RFC3339)"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.DetectionAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/pickets/{picketId}/detections [get]
func (h *DetectionHandler) GetDetectionsByPicket(c *gin.Context) {
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

	// Get picket ID from path
	picketID := c.Param("picketId")
	if picketID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing picketId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "picketId is required", nil)

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.detection.list"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  picketID,
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
	var filter models.DetectionFilter
	if sensorID := c.Query("sensorId"); sensorID != "" {
		filter.SensorID = sensorID
	}

	if ruleSetID := c.Query("ruleSetId"); ruleSetID != "" {
		filter.RuleSetID = ruleSetID
	}

	if ruleID := c.Query("ruleId"); ruleID != "" {
		filter.RuleID = ruleID
	}

	if eventType := c.Query("eventType"); eventType != "" {
		filter.EventType = eventType
	}

	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}

	if startTime := c.Query("startTime"); startTime != "" {
		filter.StartTime = startTime
	}

	if endTime := c.Query("endTime"); endTime != "" {
		filter.EndTime = endTime
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

	opts := models.ListDetectionsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetByPicketID(ctx, logger, subject, picketID, opts)
	if err != nil {
		logger.Error(err, "failed to get detections by picket", "picketId", picketID)
		response.SendError(c, http.StatusInternalServerError, "get_detections_by_picket_failed", "Failed to get detections by picket", err.Error())

		return
	}

	// Convert to API models
	apiDetections := make([]*models.DetectionAPI, len(result.Items))
	for i, d := range result.Items {
		apiDetections[i] = d.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detections by picket retrieved successfully", "picketId", picketID, "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Detections by picket retrieved successfully", apiDetections)
}

// GetDetectionsByRuleSet returns detections for a specific rule set.
// @Summary      Get detections by rule set
// @Description  Returns detections for a specific rule set
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        ruleSetId path string true "Rule Set ID"
// @Param        sensorId query string false "Filter by sensor ID"
// @Param        picketId query string false "Filter by Picket ID"
// @Param        ruleId query string false "Filter by rule ID"
// @Param        eventType query string false "Filter by event type"
// @Param        severity query string false "Filter by severity"
// @Param        startTime query string false "Filter by start time (RFC3339)"
// @Param        endTime query string false "Filter by end time (RFC3339)"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.DetectionAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/{ruleSetId}/detections [get]
func (h *DetectionHandler) GetDetectionsByRuleSet(c *gin.Context) {
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

	// Get rule set ID from path
	ruleSetID := c.Param("ruleSetId")
	if ruleSetID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing ruleSetId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "ruleSetId is required", nil)

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.detection.list"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  ruleSetID,
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
	var filter models.DetectionFilter
	if sensorID := c.Query("sensorId"); sensorID != "" {
		filter.SensorID = sensorID
	}

	if picketID := c.Query("picketId"); picketID != "" {
		filter.PicketID = picketID
	}

	if ruleID := c.Query("ruleId"); ruleID != "" {
		filter.RuleID = ruleID
	}

	if eventType := c.Query("eventType"); eventType != "" {
		filter.EventType = eventType
	}

	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}

	if startTime := c.Query("startTime"); startTime != "" {
		filter.StartTime = startTime
	}

	if endTime := c.Query("endTime"); endTime != "" {
		filter.EndTime = endTime
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

	opts := models.ListDetectionsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetByRuleSetID(ctx, logger, subject, ruleSetID, opts)
	if err != nil {
		logger.Error(err, "failed to get detections by ruleSet", "ruleSetId", ruleSetID)
		response.SendError(c, http.StatusInternalServerError, "get_detections_by_ruleset_failed", "Failed to get detections by rule set", err.Error())

		return
	}

	// Convert to API models
	apiDetections := make([]*models.DetectionAPI, len(result.Items))
	for i, d := range result.Items {
		apiDetections[i] = d.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detections by ruleSet retrieved successfully", "ruleSetId", ruleSetID, "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Detections by rule set retrieved successfully", apiDetections)
}

// GetDetectionsByRule returns detections for a specific rule.
// @Summary      Get detections by rule
// @Description  Returns detections for a specific rule
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        ruleId path string true "Rule ID"
// @Param        sensorId query string false "Filter by sensor ID"
// @Param        picketId query string false "Filter by Picket ID"
// @Param        ruleSetId query string false "Filter by rule set ID"
// @Param        eventType query string false "Filter by event type"
// @Param        severity query string false "Filter by severity"
// @Param        startTime query string false "Filter by start time (RFC3339)"
// @Param        endTime query string false "Filter by end time (RFC3339)"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.DetectionAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rules/{ruleId}/detections [get]
func (h *DetectionHandler) GetDetectionsByRule(c *gin.Context) {
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

	// Get rule ID from path
	ruleID := c.Param("ruleId")
	if ruleID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing ruleId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "ruleId is required", nil)

		return
	}

	// Authorize (AuthZ check before service access)
	input := authz.NewInput(
		subject,
		types.Action("netshield.detection.list"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  ruleID,
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
	var filter models.DetectionFilter
	if sensorID := c.Query("sensorId"); sensorID != "" {
		filter.SensorID = sensorID
	}

	if picketID := c.Query("picketId"); picketID != "" {
		filter.PicketID = picketID
	}

	if ruleSetID := c.Query("ruleSetId"); ruleSetID != "" {
		filter.RuleSetID = ruleSetID
	}

	if eventType := c.Query("eventType"); eventType != "" {
		filter.EventType = eventType
	}

	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}

	if startTime := c.Query("startTime"); startTime != "" {
		filter.StartTime = startTime
	}

	if endTime := c.Query("endTime"); endTime != "" {
		filter.EndTime = endTime
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

	opts := models.ListDetectionsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetByRuleID(ctx, logger, subject, ruleID, opts)
	if err != nil {
		logger.Error(err, "failed to get detections by rule", "ruleId", ruleID)
		response.SendError(c, http.StatusInternalServerError, "get_detections_by_rule_failed", "Failed to get detections by rule", err.Error())

		return
	}

	// Convert to API models
	apiDetections := make([]*models.DetectionAPI, len(result.Items))
	for i, d := range result.Items {
		apiDetections[i] = d.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("detections by rule retrieved successfully", "ruleId", ruleID, "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Detections by rule retrieved successfully", apiDetections)
}

// GetUnprocessedDetections returns detections that have not been processed yet.
// @Summary      Get unprocessed detections
// @Description  Returns detections that have not been processed yet
// @Tags         detections
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        sensorId query string false "Filter by sensor ID"
// @Param        picketId query string false "Filter by Picket ID"
// @Param        ruleSetId query string false "Filter by rule set ID"
// @Param        ruleId query string false "Filter by rule ID"
// @Param        eventType query string false "Filter by event type"
// @Param        severity query string false "Filter by severity"
// @Param        startTime query string false "Filter by start time (RFC3339)"
// @Param        endTime query string false "Filter by end time (RFC3339)"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.DetectionAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/detections/unprocessed [get]
func (h *DetectionHandler) GetUnprocessedDetections(c *gin.Context) {
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
		types.Action("netshield.detection.list"),
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
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
	var filter models.DetectionFilter
	if sensorID := c.Query("sensorId"); sensorID != "" {
		filter.SensorID = sensorID
	}

	if picketID := c.Query("picketId"); picketID != "" {
		filter.PicketID = picketID
	}

	if ruleSetID := c.Query("ruleSetId"); ruleSetID != "" {
		filter.RuleSetID = ruleSetID
	}

	if ruleID := c.Query("ruleId"); ruleID != "" {
		filter.RuleID = ruleID
	}

	if eventType := c.Query("eventType"); eventType != "" {
		filter.EventType = eventType
	}

	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}

	if startTime := c.Query("startTime"); startTime != "" {
		filter.StartTime = startTime
	}

	if endTime := c.Query("endTime"); endTime != "" {
		filter.EndTime = endTime
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

	opts := models.ListDetectionsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetUnprocessed(ctx, logger, subject, opts)
	if err != nil {
		logger.Error(err, "failed to get unprocessed detections")
		response.SendError(c, http.StatusInternalServerError, "get_unprocessed_detections_failed", "Failed to get unprocessed detections", err.Error())

		return
	}

	// Convert to API models
	apiDetections := make([]*models.DetectionAPI, len(result.Items))
	for i, d := range result.Items {
		apiDetections[i] = d.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("unprocessed detections retrieved successfully", "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Unprocessed detections retrieved successfully", apiDetections)
}
