// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// DetectionHandler AuthZ Tests
// =============================================================================

func TestDetectionHandler_ListDetections_AuthZAllowed(t *testing.T) {
	// Setup authz mock (allow all)
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	// Create handler with mock service
	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}

	// Create router and request
	router := setupTestRouter()
	router.GET("/netshield/v1/detections", handler.ListDetections)

	req := createAuthRequest("GET", "/netshield/v1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should succeed with authz allowed
	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_ListDetections_AuthZDenied(t *testing.T) {
	// Setup authz mock (deny all)
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections", handler.ListDetections)

	req := createAuthRequest("GET", "/netshield/v1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_ListDetections_AuthZError(t *testing.T) {
	// Setup authz mock (error)
	// Note: vp-lib authz converts errors to deny decisions, so we get 403 not 500
	cleanup := initTestAuthz(false, "", errors.New("authz error"))
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections", handler.ListDetections)

	req := createAuthRequest("GET", "/netshield/v1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// vp-lib authz returns a deny decision (403) for errors, not 500
	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz errors (vp-lib behavior)")
}

func TestDetectionHandler_GetDetection_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections/:detectionId", handler.GetDetection)

	req := createAuthRequest("GET", "/netshield/v1/detections/det-123")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_GetDetection_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections/:detectionId", handler.GetDetection)

	req := createAuthRequest("GET", "/netshield/v1/detections/det-123")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_CreateDetection_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections", handler.CreateDetection)

	req := createAuthRequest("POST", "/netshield/v1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusForbidden, w.Code, "Should not be 403 when authz allows")
	assert.NotEqual(t, http.StatusUnauthorized, w.Code, "Should not be 401 when authz allows")
}

func TestDetectionHandler_CreateDetection_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections", handler.CreateDetection)

	req := createAuthRequest("POST", "/netshield/v1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_ProcessDetection_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections/:detectionId/process", handler.ProcessDetection)

	req := createAuthRequest("POST", "/netshield/v1/detections/det-123/process")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_ProcessDetection_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections/:detectionId/process", handler.ProcessDetection)

	req := createAuthRequest("POST", "/netshield/v1/detections/det-123/process")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_MarkAsProcessed_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections/:detectionId/mark-processed", handler.MarkAsProcessed)

	req := createAuthRequest("POST", "/netshield/v1/detections/det-123/mark-processed")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_MarkAsProcessed_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections/:detectionId/mark-processed", handler.MarkAsProcessed)

	req := createAuthRequest("POST", "/netshield/v1/detections/det-123/mark-processed")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_GetDetectionsBySensor_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/sensors/:picketId/detections", handler.GetDetectionsBySensor)

	req := createAuthRequest("GET", "/netshield/v1/sensors/picket-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_GetDetectionsBySensor_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/sensors/:picketId/detections", handler.GetDetectionsBySensor)

	req := createAuthRequest("GET", "/netshield/v1/sensors/picket-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_GetDetectionsByPicket_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/pickets/:picketId/detections", handler.GetDetectionsByPicket)

	req := createAuthRequest("GET", "/netshield/v1/pickets/picket-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_GetDetectionsByPicket_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/pickets/:picketId/detections", handler.GetDetectionsByPicket)

	req := createAuthRequest("GET", "/netshield/v1/pickets/picket-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_GetDetectionsByRuleSet_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets/:ruleSetId/detections", handler.GetDetectionsByRuleSet)

	req := createAuthRequest("GET", "/netshield/v1/rulesets/rs-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_GetDetectionsByRuleSet_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets/:ruleSetId/detections", handler.GetDetectionsByRuleSet)

	req := createAuthRequest("GET", "/netshield/v1/rulesets/rs-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_GetDetectionsByRule_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rules/:ruleId/detections", handler.GetDetectionsByRule)

	req := createAuthRequest("GET", "/netshield/v1/rules/rule-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_GetDetectionsByRule_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/rules/:ruleId/detections", handler.GetDetectionsByRule)

	req := createAuthRequest("GET", "/netshield/v1/rules/rule-1/detections")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestDetectionHandler_GetUnprocessedDetections_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections/unprocessed", handler.GetUnprocessedDetections)

	req := createAuthRequest("GET", "/netshield/v1/detections/unprocessed")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestDetectionHandler_GetUnprocessedDetections_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &DetectionHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections/unprocessed", handler.GetUnprocessedDetections)

	req := createAuthRequest("GET", "/netshield/v1/detections/unprocessed")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}
