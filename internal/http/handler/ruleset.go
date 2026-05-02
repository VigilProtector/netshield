// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/vp-lib/authn"
	"vigilprotector.io/vp-lib/correlation"
	ginlogging "vigilprotector.io/vp-lib/gin/logging"
	"vigilprotector.io/vp-lib/gin/response"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// RuleSetHandler handles HTTP requests for ruleset operations.
type RuleSetHandler struct {
	service service.RuleSetServiceInterface
}

// NewRuleSetHandler creates a new RuleSetHandler.
func NewRuleSetHandler(service service.RuleSetServiceInterface) *RuleSetHandler {
	return &RuleSetHandler{
		service: service,
	}
}

// ListRuleSets lists all rule sets with optional filtering.
// @Summary      List rule sets
// @Description  Returns a paginated list of NetShield rule sets
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        name query string false "Filter by rule set name"
// @Param        version query string false "Filter by version"
// @Param        source query string false "Filter by source (et-open, et-pro, custom)"
// @Param        enabled query bool false "Filter by enabled status"
// @Param        limit query int false "Number of items per page" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200 {object} response.SuccessResponse{data=[]models.RuleSetAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets [get]
func (h *RuleSetHandler) ListRuleSets(c *gin.Context) {
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
	var filter models.RuleSetFilter
	if name := c.Query("name"); name != "" {
		filter.Name = name
	}
	if version := c.Query("version"); version != "" {
		filter.Version = version
	}
	if source := c.Query("source"); source != "" {
		filter.Source = source
	}
	if enabled := c.Query("enabled"); enabled != "" {
		if enabled == "true" {
			filter.Enabled = boolPtr(true)
		} else if enabled == "false" {
			filter.Enabled = boolPtr(false)
		}
	}

	// Call service
	result, err := h.service.List(ctx, logger, subject, filter)
	if err != nil {
		logger.Error(err, "failed to list rule sets")
		response.SendError(c, http.StatusInternalServerError, "list_rulesets_failed", "Failed to list rule sets", err.Error())
		return
	}

	// Convert to API models
	apiRuleSets := make([]*models.RuleSetAPI, len(result.Items))
	for i, rs := range result.Items {
		apiRuleSets[i] = rs.ToAPI()
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("rule sets listed successfully", "count", len(result.Items))
	response.SendResponse(c, http.StatusOK, "Rule sets listed successfully", apiRuleSets)
}

// GetRuleSet returns a single rule set by ID.
// @Summary      Get rule set
// @Description  Returns a single NetShield rule set by ID
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Rule Set ID"
// @Success      200 {object} response.SuccessResponse{data=models.RuleSetAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/{id} [get]
func (h *RuleSetHandler) GetRuleSet(c *gin.Context) {
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
	id := c.Param("id")
	if id == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing id parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "id is required", nil)
		return
	}

	// Call service
	ruleSet, err := h.service.Get(ctx, logger, subject, id)
	if err != nil {
		logger.Error(err, "failed to get rule set", "id", id)
		response.SendError(c, http.StatusInternalServerError, "get_ruleset_failed", "Failed to get rule set", err.Error())
		return
	}

	if ruleSet == nil {
		response.SendError(c, http.StatusNotFound, "ruleset_not_found", "Rule set not found", nil)
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("rule set retrieved successfully", "id", id)
	response.SendResponse(c, http.StatusOK, "Rule set retrieved successfully", ruleSet.ToAPI())
}

// CreateRuleSet creates a new rule set.
// @Summary      Create rule set
// @Description  Creates a new NetShield rule set
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body models.CreateRuleSetRequest true "Rule set creation request"
// @Success      201 {object} response.SuccessResponse{data=models.RuleSetAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      409 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets [post]
func (h *RuleSetHandler) CreateRuleSet(c *gin.Context) {
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
	var req models.CreateRuleSetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error(err, "failed to parse request body")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid request body", err.Error())
		return
	}

	// Call service
	ruleSet, err := h.service.Create(ctx, logger, subject, req)
	if err != nil {
		logger.Error(err, "failed to create rule set")

		// Handle specific errors
		if errors.Is(err, service.ErrRuleSetAlreadyExists) {
			response.SendError(c, http.StatusConflict, "ruleset_already_exists", "Rule set already exists", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "create_ruleset_failed", "Failed to create rule set", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("rule set created successfully", "id", ruleSet.ID, "name", ruleSet.Name)
	response.SendResponse(c, http.StatusCreated, "Rule set created successfully", ruleSet.ToAPI())
}

// UpdateRuleSet updates an existing rule set.
// @Summary      Update rule set
// @Description  Updates an existing NetShield rule set
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Rule Set ID"
// @Param        request body models.UpdateRuleSetRequest true "Rule set update request"
// @Success      200 {object} response.SuccessResponse{data=models.RuleSetAPI}
// @Failure      400 {object} response.ErrorResponse
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/{id} [patch]
func (h *RuleSetHandler) UpdateRuleSet(c *gin.Context) {
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
	id := c.Param("id")
	if id == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing id parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "id is required", nil)
		return
	}

	// Parse request body
	var req models.UpdateRuleSetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error(err, "failed to parse request body")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "Invalid request body", err.Error())
		return
	}

	// Call service
	ruleSet, err := h.service.Update(ctx, logger, subject, id, req)
	if err != nil {
		logger.Error(err, "failed to update rule set", "id", id)

		// Handle specific errors
		if errors.Is(err, service.ErrRuleSetNotFound) {
			response.SendError(c, http.StatusNotFound, "ruleset_not_found", "Rule set not found", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "update_ruleset_failed", "Failed to update rule set", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("rule set updated successfully", "id", id)
	response.SendResponse(c, http.StatusOK, "Rule set updated successfully", ruleSet.ToAPI())
}

// DeleteRuleSet deletes a rule set by ID.
// @Summary      Delete rule set
// @Description  Deletes a NetShield rule set by ID
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Rule Set ID"
// @Success      200 {object} response.SuccessResponse{data=string}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/{id} [delete]
func (h *RuleSetHandler) DeleteRuleSet(c *gin.Context) {
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
	id := c.Param("id")
	if id == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing id parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "id is required", nil)
		return
	}

	// Call service
	err = h.service.Delete(ctx, logger, subject, id)
	if err != nil {
		logger.Error(err, "failed to delete rule set", "id", id)

		// Handle specific errors
		if errors.Is(err, service.ErrRuleSetNotFound) {
			response.SendError(c, http.StatusNotFound, "ruleset_not_found", "Rule set not found", err.Error())
			return
		}
		if errors.Is(err, service.ErrDefaultRuleSetCannotDelete) {
			response.SendError(c, http.StatusBadRequest, "cannot_delete_default", "Cannot delete default rule set", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "delete_ruleset_failed", "Failed to delete rule set", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("rule set deleted successfully", "id", id)
	response.SendResponse(c, http.StatusOK, "Rule set deleted successfully", nil)
}

// EnableRuleSet enables a rule set by ID.
// @Summary      Enable rule set
// @Description  Enables a NetShield rule set by ID
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Rule Set ID"
// @Success      200 {object} response.SuccessResponse{data=models.RuleSetAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/{id}/enable [post]
func (h *RuleSetHandler) EnableRuleSet(c *gin.Context) {
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
	id := c.Param("id")
	if id == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing id parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "id is required", nil)
		return
	}

	// Call service
	ruleSet, err := h.service.Enable(ctx, logger, subject, id)
	if err != nil {
		logger.Error(err, "failed to enable rule set", "id", id)

		// Handle specific errors
		if errors.Is(err, service.ErrRuleSetNotFound) {
			response.SendError(c, http.StatusNotFound, "ruleset_not_found", "Rule set not found", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "enable_ruleset_failed", "Failed to enable rule set", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("rule set enabled successfully", "id", id)
	response.SendResponse(c, http.StatusOK, "Rule set enabled successfully", ruleSet.ToAPI())
}

// DisableRuleSet disables a rule set by ID.
// @Summary      Disable rule set
// @Description  Disables a NetShield rule set by ID
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Rule Set ID"
// @Success      200 {object} response.SuccessResponse{data=models.RuleSetAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/{id}/disable [post]
func (h *RuleSetHandler) DisableRuleSet(c *gin.Context) {
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
	id := c.Param("id")
	if id == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing id parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "id is required", nil)
		return
	}

	// Call service
	ruleSet, err := h.service.Disable(ctx, logger, subject, id)
	if err != nil {
		logger.Error(err, "failed to disable rule set", "id", id)

		// Handle specific errors
		if errors.Is(err, service.ErrRuleSetNotFound) {
			response.SendError(c, http.StatusNotFound, "ruleset_not_found", "Rule set not found", err.Error())
			return
		}
		if errors.Is(err, service.ErrDefaultRuleSetCannotDisable) {
			response.SendError(c, http.StatusBadRequest, "cannot_disable_default", "Cannot disable default rule set", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "disable_ruleset_failed", "Failed to disable rule set", err.Error())
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("rule set disabled successfully", "id", id)
	response.SendResponse(c, http.StatusOK, "Rule set disabled successfully", ruleSet.ToAPI())
}

// GetDefaultRuleSet returns the default rule set.
// @Summary      Get default rule set
// @Description  Returns the default NetShield rule set (ET Open Baseline)
// @Tags         rulesets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} response.SuccessResponse{data=models.RuleSetAPI}
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/default [get]
func (h *RuleSetHandler) GetDefaultRuleSet(c *gin.Context) {
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

	// Call service
	ruleSet, err := h.service.GetDefault(ctx, logger, subject)
	if err != nil {
		logger.Error(err, "failed to get default rule set")
		response.SendError(c, http.StatusInternalServerError, "get_default_ruleset_failed", "Failed to get default rule set", err.Error())
		return
	}

	if ruleSet == nil {
		response.SendError(c, http.StatusNotFound, "default_ruleset_not_found", "Default rule set not found", nil)
		return
	}

	// Success response
	logger.V(vplogging.LogLevelVerbose).Info("default rule set retrieved successfully")
	response.SendResponse(c, http.StatusOK, "Default rule set retrieved successfully", ruleSet.ToAPI())
}

// RenderRuleSet renders a rule set into Suricata-compatible format.
// @Summary      Render rule set
// @Description  Renders a rule set into Suricata-compatible format
// @Tags         rulesets
// @Accept       json
// @Produce      plain
// @Security     BearerAuth
// @Param        id path string true "Rule Set ID"
// @Success      200 {string} string "Suricata rules in text format"
// @Failure      401 {object} response.ErrorResponse
// @Failure      404 {object} response.ErrorResponse
// @Failure      500 {object} response.ErrorResponse
// @Router       /netshield/v1/rulesets/{id}/render [get]
func (h *RuleSetHandler) RenderRuleSet(c *gin.Context) {
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
	id := c.Param("id")
	if id == "" {
		logger.V(vplogging.LogLevelInfo).Error(nil, "missing id parameter")
		response.SendError(c, http.StatusBadRequest, "invalid_request", "id is required", nil)
		return
	}

	// Call service
	rules, err := h.service.Render(ctx, logger, subject, id)
	if err != nil {
		logger.Error(err, "failed to render rule set", "id", id)

		// Handle specific errors
		if errors.Is(err, service.ErrRuleSetNotFound) {
			response.SendError(c, http.StatusNotFound, "ruleset_not_found", "Rule set not found", err.Error())
			return
		}

		response.SendError(c, http.StatusInternalServerError, "render_ruleset_failed", "Failed to render rule set", err.Error())
		return
	}

	// Success response - return as plain text
	logger.V(vplogging.LogLevelVerbose).Info("rule set rendered successfully", "id", id)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, rules)
}

// Helper functions

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}
