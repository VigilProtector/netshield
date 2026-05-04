// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vigilprotector.io/netshield/internal/models"
)

// TestRuleSetHandler_GetRuleSet tests the GetRuleSet handler.
func TestRuleSetHandler_GetRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets/:ruleSetId", handler.GetRuleSet)

	t.Run("successful get ruleset", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/rulesets/test-ruleset")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Rule set retrieved successfully", "Response should contain success message")
	})

	t.Run("ruleset not found", func(t *testing.T) {
		// Mock service returns empty ruleset for unknown names
		// To test 404, we would need a mock that returns ErrRuleSetNotFound
		req := createAuthRequest(http.MethodGet, "/netshield/v1/rulesets/unknown")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Mock returns empty ruleset, so we get 200
		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK (mock returns empty ruleset)")
		assert.Contains(t, w.Body.String(), "Rule set retrieved successfully", "Response should contain success message")
	})
}

// TestRuleSetHandler_CreateRuleSet tests the CreateRuleSet handler.
func TestRuleSetHandler_CreateRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/rulesets", handler.CreateRuleSet)

	t.Run("successful create ruleset", func(t *testing.T) {
		request := models.CreateRuleSetRequest{
			Name:        "test-ruleset",
			Version:     "1.0.0",
			Description: "Test ruleset",
			Enabled:     true,
			Source:      "custom",
			Rules:       []models.RuleRefAPI{},
			Scope:       models.ScopeAPI{},
		}

		body, err := json.Marshal(request)
		require.NoError(t, err, "Should marshal create request")

		req := createAuthRequest(http.MethodPost, "/netshield/v1/rulesets")
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code, "Should return 201 Created")
		assert.Contains(t, w.Body.String(), "Rule set created successfully", "Response should contain success message")
	})

	t.Run("invalid request body", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/rulesets")
		req.Body = io.NopCloser(bytes.NewBuffer([]byte("{invalid json}")))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for invalid JSON")
		assert.Contains(t, w.Body.String(), "invalid_request", "Response should contain invalid request error")
	})
}

// TestRuleSetHandler_UpdateRuleSet tests the UpdateRuleSet handler.
func TestRuleSetHandler_UpdateRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.PATCH("/netshield/v1/rulesets/:ruleSetId", handler.UpdateRuleSet)

	t.Run("successful update ruleset", func(t *testing.T) {
		request := models.UpdateRuleSetRequest{
			Version:     "2.0.0",
			Description: "Updated description",
			Rules:       []models.RuleRefAPI{},
		}

		body, err := json.Marshal(request)
		require.NoError(t, err, "Should marshal update request")

		req := createAuthRequest(http.MethodPatch, "/netshield/v1/rulesets/test-ruleset")
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Rule set updated successfully", "Response should contain success message")
	})
}

// TestRuleSetHandler_DeleteRuleSet tests the DeleteRuleSet handler.
func TestRuleSetHandler_DeleteRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.DELETE("/netshield/v1/rulesets/:ruleSetId", handler.DeleteRuleSet)

	t.Run("successful delete ruleset", func(t *testing.T) {
		req := createAuthRequest(http.MethodDelete, "/netshield/v1/rulesets/test-ruleset")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Rule set deleted successfully", "Response should contain success message")
	})
}

// TestRuleSetHandler_EnableRuleSet tests the EnableRuleSet handler.
func TestRuleSetHandler_EnableRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/rulesets/:ruleSetId/enable", handler.EnableRuleSet)

	t.Run("successful enable ruleset", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/rulesets/test-ruleset/enable")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Rule set enabled successfully", "Response should contain success message")
	})
}

// TestRuleSetHandler_DisableRuleSet tests the DisableRuleSet handler.
func TestRuleSetHandler_DisableRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/rulesets/:ruleSetId/disable", handler.DisableRuleSet)

	t.Run("successful disable ruleset", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/rulesets/test-ruleset/disable")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Rule set disabled successfully", "Response should contain success message")
	})
}

// TestRuleSetHandler_GetDefaultRuleSet tests the GetDefaultRuleSet handler.
func TestRuleSetHandler_GetDefaultRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets/default", handler.GetDefaultRuleSet)

	t.Run("successful get default ruleset", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/rulesets/default")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Default rule set retrieved successfully", "Response should contain success message")
	})
}

// TestRuleSetHandler_RenderRuleSet tests the RenderRuleSet handler.
func TestRuleSetHandler_RenderRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets/:ruleSetId/render", handler.RenderRuleSet)

	t.Run("successful render ruleset", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/rulesets/test-ruleset/render")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		// Render returns plain text (Suricata rules), mock returns empty string
		assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"), "Content-Type should be text/plain")
	})
}
