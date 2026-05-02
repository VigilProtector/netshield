// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/vp-lib/authn"
	"vigilprotector.io/vp-lib/correlation"
	ginlogging "vigilprotector.io/vp-lib/gin/logging"
	"vigilprotector.io/vp-lib/gin/response"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// FindingHandler handles HTTP requests for finding operations.
type FindingHandler struct {
	service service.FindingServiceInterface
}

// NewFindingHandler creates a new FindingHandler.
func NewFindingHandler(service service.FindingServiceInterface) *FindingHandler {
	return &FindingHandler{
		service: service,
	}
}

// ListFindings lists all findings with optional filtering.
// @Summary      List findings
// @Description  Returns a paginated list of NetShield findings
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        findingType query string false "Filter by finding type"
// @Param        sourceContext query string false "Filter by source context"
// @Param        assetId query string false "Filter by asset ID"
// @Param        defconId query string false "Filter by Defcon ID"
// @Param        severity query string false "Filter by severity"
// @Param        lifecycle query string false "Filter by lifecycle status"
// @Param        verification query string false "Filter by verification status"
// @Param        freshness query string false "Filter by freshness status"
// @Param        startTime query string false "Filter by start time (RFC3339)"
// @Param        endTime query string false "Filter by end time (RFC3339)"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.FindingAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings [get]
func (h *FindingHandler) ListFindings(c *gin.Context) {
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

	// Parse query parameters
	var filter models.FindingFilter
	if findingType := c.Query("findingType"); findingType != "" {
		filter.FindingType = findingType
	}
	if sourceContext := c.Query("sourceContext"); sourceContext != "" {
		filter.SourceContext = sourceContext
	}
	if assetID := c.Query("assetId"); assetID != "" {
		filter.AssetID = assetID
	}
	if defconID := c.Query("defconId"); defconID != "" {
		filter.DefconID = defconID
	}
	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}
	if lifecycle := c.Query("lifecycle"); lifecycle != "" {
		filter.Lifecycle = lifecycle
	}
	if verification := c.Query("verification"); verification != "" {
		filter.Verification = verification
	}
	if freshness := c.Query("freshness"); freshness != "" {
		filter.Freshness = freshness
	}
	if startTime := c.Query("startTime"); startTime != "" {
		filter.StartTime = startTime
	}
	if endTime := c.Query("endTime"); endTime != "" {
		filter.EndTime = endTime
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

	opts := models.ListFindingsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.List(ctx, logger, subject, opts)
	if err != nil {
		logger.Error(err, "failed to list findings")
		response.SendError(c, http.StatusInternalServerError, "list_findings_failed", "Failed to list findings", err.Error())
		return
	}

	// Convert to API models
	apiFindings := make([]*models.FindingAPI, len(result.Items))
	for i, f := range result.Items {
		apiFindings[i] = f.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("findings listed successfully", "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Findings listed successfully", apiFindings)
}

// GetFinding returns a single finding by ID.
// @Summary      Get finding
// @Description  Returns a single NetShield finding by finding ID
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        findingId path string true "Finding ID"
// @Success      200 {object} response.SuccessResponse{data=models.FindingAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings/{findingId} [get]
func (h *FindingHandler) GetFinding(c *gin.Context) {
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

	// Get finding ID from path
	findingID := c.Param("findingId")
	if findingID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing findingId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "findingId is required", nil)
		return
	}

	// Call service
	finding, err := h.service.Get(ctx, logger, subject, findingID)
	if err != nil {
		logger.Error(err, "failed to get finding", "findingId", findingID)
		response.SendError(c, http.StatusInternalServerError, "get_finding_failed", "Failed to get finding", err.Error())
		return
	}

	if finding == nil {
		response.SendError(c, http.StatusNotFound, "finding_not_found", "Finding not found", nil)
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("finding retrieved successfully", "findingId", findingID)
	response.SendResponse(c, http.StatusOK, "Finding retrieved successfully", finding.ToAPI())
}

// CreateFinding creates a new finding.
// @Summary      Create finding
// @Description  Creates a new NetShield finding
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body models.FindingAPI true "Finding creation request"
// @Success      201 {object} response.SuccessResponse{data=models.FindingAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      409 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings [post]
func (h *FindingHandler) CreateFinding(c *gin.Context) {
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

	// Parse request body
	var req models.FindingAPI
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error(err, "failed to parse request body")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid request body", err.Error())
		return
	}

	// Convert to internal model
	finding, err := req.FromAPI()
	if err != nil {
		logger.Error(err, "failed to convert from API model")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid finding data", err.Error())
		return
	}

	// Call service
	finding, err = h.service.Create(ctx, logger, subject, finding)
	if err != nil {
		logger.Error(err, "failed to create finding")

		// Handle specific errors
		if errors.Is(err, service.ErrFindingAlreadyExists) {
			response.SendError(c, http.StatusConflict, "finding_already_exists", "Finding already exists", err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidFindingType) {
			response.SendError(c, http.StatusBadRequest, "invalid_finding_type", "Invalid finding type", err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidSeverity) {
			response.SendError(c, http.StatusBadRequest, "invalid_severity", "Invalid severity", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "create_finding_failed", "Failed to create finding", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("finding created successfully", "findingId", finding.FindingID)
	response.SendResponse(c, http.StatusCreated, "Finding created successfully", finding.ToAPI())
}

// UpdateFindingLifecycle updates the lifecycle status of a finding.
// @Summary      Update finding lifecycle
// @Description  Updates the lifecycle status of a finding (open -> resolved -> closed)
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        findingId path string true "Finding ID"
// @Param        request body models.UpdateFindingLifecycleRequest true "Lifecycle update request"
// @Success      200 {object} response.SuccessResponse{data=models.FindingAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings/{findingId}/lifecycle [patch]
func (h *FindingHandler) UpdateFindingLifecycle(c *gin.Context) {
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

	// Get finding ID from path
	findingID := c.Param("findingId")
	if findingID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing findingId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "findingId is required", nil)
		return
	}

	// Parse request body
	var req models.UpdateFindingLifecycleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error(err, "failed to parse request body")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid request body", err.Error())
		return
	}

	// Call service
	finding, err := h.service.UpdateLifecycle(ctx, logger, subject, findingID, req)
	if err != nil {
		logger.Error(err, "failed to update finding lifecycle", "findingId", findingID)

		// Handle specific errors
		if errors.Is(err, service.ErrFindingNotFound) {
			response.SendError(c, http.StatusNotFound, "finding_not_found", "Finding not found", err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidLifecycleTransition) {
			response.SendError(c, http.StatusBadRequest, "invalid_lifecycle_transition", "Invalid lifecycle transition", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "update_lifecycle_failed", "Failed to update lifecycle", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("finding lifecycle updated successfully", "findingId", findingID)
	response.SendResponse(c, http.StatusOK, "Finding lifecycle updated successfully", finding.ToAPI())
}

// UpdateFindingVerification updates the verification status of a finding.
// @Summary      Update finding verification
// @Description  Updates the verification status of a finding
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        findingId path string true "Finding ID"
// @Param        request body models.UpdateFindingVerificationRequest true "Verification update request"
// @Success      200 {object} response.SuccessResponse{data=models.FindingAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings/{findingId}/verification [patch]
func (h *FindingHandler) UpdateFindingVerification(c *gin.Context) {
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

	// Get finding ID from path
	findingID := c.Param("findingId")
	if findingID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing findingId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "findingId is required", nil)
		return
	}

	// Parse request body
	var req models.UpdateFindingVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error(err, "failed to parse request body")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid request body", err.Error())
		return
	}

	// Call service
	finding, err := h.service.UpdateVerification(ctx, logger, subject, findingID, req)
	if err != nil {
		logger.Error(err, "failed to update finding verification", "findingId", findingID)

		// Handle specific errors
		if errors.Is(err, service.ErrFindingNotFound) {
			response.SendError(c, http.StatusNotFound, "finding_not_found", "Finding not found", err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidVerificationStatus) {
			response.SendError(c, http.StatusBadRequest, "invalid_verification_status", "Invalid verification status", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "update_verification_failed", "Failed to update verification", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("finding verification updated successfully", "findingId", findingID)
	response.SendResponse(c, http.StatusOK, "Finding verification updated successfully", finding.ToAPI())
}

// MarkFindingsStale marks findings as stale based on freshness thresholds.
// @Summary      Mark findings stale
// @Description  Marks findings as stale based on freshness thresholds
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        staleAfter query string false "Duration after which findings are considered stale (e.g., 24h, 7d)" default("720h")
// @Success      200 {object} response.SuccessResponse{data=int}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings/mark-stale [post]
func (h *FindingHandler) MarkFindingsStale(c *gin.Context) {
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

	// Parse staleAfter duration
	staleAfterStr := c.Query("staleAfter")
	if staleAfterStr == "" {
		staleAfterStr = "720h" // Default: 30 days
	}

	staleAfter, err := time.ParseDuration(staleAfterStr)
	if err != nil {
		logger.Error(err, "failed to parse staleAfter duration")
		response.SendError(c, http.StatusBadRequest, "invalid_duration", "Invalid duration format. Use format like '24h', '7d', '168h'", err.Error())
		return
	}

	// Call service
	count, err := h.service.MarkStale(ctx, logger, subject, staleAfter)
	if err != nil {
		logger.Error(err, "failed to mark findings as stale")
		response.SendError(c, http.StatusInternalServerError, "mark_stale_failed", "Failed to mark findings as stale", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("findings marked as stale successfully", "count", count)
	response.SendResponse(c, http.StatusOK, fmt.Sprintf("Marked %d findings as stale", count), count)
}

// GetFindingsByAsset returns findings for a specific asset.
// @Summary      Get findings by asset
// @Description  Returns findings for a specific asset
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        assetId path string true "Asset ID"
// @Param        findingType query string false "Filter by finding type"
// @Param        severity query string false "Filter by severity"
// @Param        lifecycle query string false "Filter by lifecycle status"
// @Param        verification query string false "Filter by verification status"
// @Param        freshness query string false "Filter by freshness status"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.FindingAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/assets/{assetId}/findings [get]
func (h *FindingHandler) GetFindingsByAsset(c *gin.Context) {
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

	// Get asset ID from path
	assetID := c.Param("assetId")
	if assetID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing assetId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "assetId is required", nil)
		return
	}

	// Parse query parameters
	var filter models.FindingFilter
	if findingType := c.Query("findingType"); findingType != "" {
		filter.FindingType = findingType
	}
	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}
	if lifecycle := c.Query("lifecycle"); lifecycle != "" {
		filter.Lifecycle = lifecycle
	}
	if verification := c.Query("verification"); verification != "" {
		filter.Verification = verification
	}
	if freshness := c.Query("freshness"); freshness != "" {
		filter.Freshness = freshness
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

	opts := models.ListFindingsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetByAsset(ctx, logger, subject, assetID, opts)
	if err != nil {
		logger.Error(err, "failed to get findings by asset", "assetId", assetID)
		response.SendError(c, http.StatusInternalServerError, "get_findings_by_asset_failed", "Failed to get findings by asset", err.Error())
		return
	}

	// Convert to API models
	apiFindings := make([]*models.FindingAPI, len(result.Items))
	for i, f := range result.Items {
		apiFindings[i] = f.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("findings by asset retrieved successfully", "assetId", assetID, "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Findings by asset retrieved successfully", apiFindings)
}

// GetFindingsByDefcon returns findings for a specific Defcon.
// @Summary      Get findings by Defcon
// @Description  Returns findings for a specific Defcon
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        defconId path string true "Defcon ID"
// @Param        findingType query string false "Filter by finding type"
// @Param        severity query string false "Filter by severity"
// @Param        lifecycle query string false "Filter by lifecycle status"
// @Param        verification query string false "Filter by verification status"
// @Param        freshness query string false "Filter by freshness status"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.FindingAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/defcons/{defconId}/findings [get]
func (h *FindingHandler) GetFindingsByDefcon(c *gin.Context) {
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

	// Get Defcon ID from path
	defconID := c.Param("defconId")
	if defconID == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing defconId parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "defconId is required", nil)
		return
	}

	// Parse query parameters
	var filter models.FindingFilter
	if findingType := c.Query("findingType"); findingType != "" {
		filter.FindingType = findingType
	}
	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}
	if lifecycle := c.Query("lifecycle"); lifecycle != "" {
		filter.Lifecycle = lifecycle
	}
	if verification := c.Query("verification"); verification != "" {
		filter.Verification = verification
	}
	if freshness := c.Query("freshness"); freshness != "" {
		filter.Freshness = freshness
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

	opts := models.ListFindingsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetByDefcon(ctx, logger, subject, defconID, opts)
	if err != nil {
		logger.Error(err, "failed to get findings by defcon", "defconId", defconID)
		response.SendError(c, http.StatusInternalServerError, "get_findings_by_defcon_failed", "Failed to get findings by defcon", err.Error())
		return
	}

	// Convert to API models
	apiFindings := make([]*models.FindingAPI, len(result.Items))
	for i, f := range result.Items {
		apiFindings[i] = f.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("findings by defcon retrieved successfully", "defconId", defconID, "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Findings by defcon retrieved successfully", apiFindings)
}

// GetFindingsByType returns findings of a specific type.
// @Summary      Get findings by type
// @Description  Returns findings of a specific finding type
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        findingType path string true "Finding Type"
// @Param        assetId query string false "Filter by asset ID"
// @Param        defconId query string false "Filter by Defcon ID"
// @Param        severity query string false "Filter by severity"
// @Param        lifecycle query string false "Filter by lifecycle status"
// @Param        verification query string false "Filter by verification status"
// @Param        freshness query string false "Filter by freshness status"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.FindingAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings/types/{findingType} [get]
func (h *FindingHandler) GetFindingsByType(c *gin.Context) {
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

	// Get finding type from path
	findingType := c.Param("findingType")
	if findingType == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing findingType parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "findingType is required", nil)
		return
	}

	// Parse query parameters
	var filter models.FindingFilter
	if assetID := c.Query("assetId"); assetID != "" {
		filter.AssetID = assetID
	}
	if defconID := c.Query("defconId"); defconID != "" {
		filter.DefconID = defconID
	}
	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}
	if lifecycle := c.Query("lifecycle"); lifecycle != "" {
		filter.Lifecycle = lifecycle
	}
	if verification := c.Query("verification"); verification != "" {
		filter.Verification = verification
	}
	if freshness := c.Query("freshness"); freshness != "" {
		filter.Freshness = freshness
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

	opts := models.ListFindingsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service - convert string to FindingType
	findingTypeEnum := models.FindingType(findingType)
	result, err := h.service.GetByType(ctx, logger, subject, findingTypeEnum, opts)
	if err != nil {
		logger.Error(err, "failed to get findings by type", "findingType", findingType)

		// Handle specific errors
		if errors.Is(err, service.ErrInvalidFindingType) {
			response.SendError(c, http.StatusBadRequest, "invalid_finding_type", "Invalid finding type", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "get_findings_by_type_failed", "Failed to get findings by type", err.Error())
		return
	}

	// Convert to API models
	apiFindings := make([]*models.FindingAPI, len(result.Items))
	for i, f := range result.Items {
		apiFindings[i] = f.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("findings by type retrieved successfully", "findingType", findingType, "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Findings by type retrieved successfully", apiFindings)
}

// GetStaleFindings returns findings that are stale.
// @Summary      Get stale findings
// @Description  Returns findings that are marked as stale
// @Tags         findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        findingType query string false "Filter by finding type"
// @Param        assetId query string false "Filter by asset ID"
// @Param        defconId query string false "Filter by Defcon ID"
// @Param        severity query string false "Filter by severity"
// @Param        lifecycle query string false "Filter by lifecycle status"
// @Param        verification query string false "Filter by verification status"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.FindingAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/findings/stale [get]
func (h *FindingHandler) GetStaleFindings(c *gin.Context) {
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

	// Parse query parameters
	var filter models.FindingFilter
	if findingType := c.Query("findingType"); findingType != "" {
		filter.FindingType = findingType
	}
	if assetID := c.Query("assetId"); assetID != "" {
		filter.AssetID = assetID
	}
	if defconID := c.Query("defconId"); defconID != "" {
		filter.DefconID = defconID
	}
	if severity := c.Query("severity"); severity != "" {
		filter.Severity = severity
	}
	if lifecycle := c.Query("lifecycle"); lifecycle != "" {
		filter.Lifecycle = lifecycle
	}
	if verification := c.Query("verification"); verification != "" {
		filter.Verification = verification
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

	opts := models.ListFindingsOptions{
		Filter: filter,
		Limit:  limit,
		Offset: offset,
	}

	// Call service
	result, err := h.service.GetStale(ctx, logger, subject, opts)
	if err != nil {
		logger.Error(err, "failed to get stale findings")
		response.SendError(c, http.StatusInternalServerError, "get_stale_findings_failed", "Failed to get stale findings", err.Error())
		return
	}

	// Convert to API models
	apiFindings := make([]*models.FindingAPI, len(result.Items))
	for i, f := range result.Items {
		apiFindings[i] = f.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("stale findings retrieved successfully", "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Stale findings retrieved successfully", apiFindings)
}
