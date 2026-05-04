// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// FindingHandler AuthZ Tests
// =============================================================================

func TestFindingHandler_ListFindings_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/findings", handler.ListFindings)

	req := createAuthRequest("GET", "/netshield/v1/findings")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestFindingHandler_ListFindings_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &FindingHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/findings", handler.ListFindings)

	req := createAuthRequest("GET", "/netshield/v1/findings")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestFindingHandler_ListFindings_AuthZError(t *testing.T) {
	cleanup := initTestAuthz(false, "", errors.New("authz error"))
	defer cleanup()

	handler := &FindingHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/findings", handler.ListFindings)

	req := createAuthRequest("GET", "/netshield/v1/findings")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// vp-lib authz returns a deny decision (403) for errors, not 500
	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz errors (vp-lib behavior)")
}

func TestFindingHandler_CreateFinding_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/findings", handler.CreateFinding)

	// Create a request with minimal valid JSON body
	// Note: FindingAPI requires occurredAt, createdAt, updatedAt as RFC3339 strings
	body := []byte(`{
		"findingId": "finding-1",
		"schemaVersion": "2.0",
		"findingType": "network.anomaly_detection",
		"sourceContext": "netshield",
		"severity": "high",
		"confidence": 0.9,
		"title": "Test Finding",
		"occurredAt": "2026-01-01T00:00:00Z",
		"createdAt": "2026-01-01T00:00:00Z",
		"updatedAt": "2026-01-01T00:00:00Z",
		"lifecycle": {"status": "new"},
		"verification": {"status": "unverified"},
		"freshness": {"status": "fresh"}
	}`)
	req := createAuthRequest("POST", "/netshield/v1/findings")
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code, "Should be 201 when authz allows and service creates finding")
}

func TestFindingHandler_CreateFinding_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &FindingHandler{}
	router := setupTestRouter()
	router.POST("/netshield/v1/findings", handler.CreateFinding)

	// For denied tests, we don't need a valid body since AuthZ will block before parsing
	req := createAuthRequest("POST", "/netshield/v1/findings")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

// Note: UpdateFindingVerification doesn't have AuthZ check in the handler,
// so we don't test it for AuthZ. Only ListFindings, GetFinding, and CreateFinding have AuthZ.
func TestFindingHandler_GetFinding_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/findings/:findingId", handler.GetFinding)

	req := createAuthRequest("GET", "/netshield/v1/findings/finding-1")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestFindingHandler_GetFinding_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &FindingHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/findings/:findingId", handler.GetFinding)

	req := createAuthRequest("GET", "/netshield/v1/findings/finding-1")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

// Other FindingHandler methods don't have AuthZ checks
