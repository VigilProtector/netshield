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

// TestFindingHandler_UpdateFindingLifecycle tests the UpdateFindingLifecycle handler.
func TestFindingHandler_UpdateFindingLifecycle(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.PATCH("/netshield/v1/findings/:findingId/lifecycle", handler.UpdateFindingLifecycle)

	t.Run("successful update lifecycle", func(t *testing.T) {
		request := models.UpdateFindingLifecycleRequest{
			Status: "active",
		}

		body, err := json.Marshal(request)
		require.NoError(t, err, "Should marshal lifecycle update request")

		req := createAuthRequest(http.MethodPatch, "/netshield/v1/findings/finding-1/lifecycle")
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Finding lifecycle updated successfully", "Response should contain success message")
	})

	t.Run("invalid request body", func(t *testing.T) {
		req := createAuthRequest(http.MethodPatch, "/netshield/v1/findings/finding-1/lifecycle")
		req.Body = io.NopCloser(bytes.NewBuffer([]byte("{invalid json}")))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for invalid JSON")
		assert.Contains(t, w.Body.String(), "invalid_request", "Response should contain invalid request error")
	})

	t.Run("missing findingId parameter", func(t *testing.T) {
		req := createAuthRequest(http.MethodPatch, "/netshield/v1/findings//lifecycle")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for missing findingId")
		assert.Contains(t, w.Body.String(), "findingId is required", "Response should contain missing findingId error")
	})
}

// TestFindingHandler_UpdateFindingVerification tests the UpdateFindingVerification handler.
func TestFindingHandler_UpdateFindingVerification(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.PATCH("/netshield/v1/findings/:findingId/verification", handler.UpdateFindingVerification)

	t.Run("successful update verification", func(t *testing.T) {
		request := models.UpdateFindingVerificationRequest{
			Status: "confirmed",
		}

		body, err := json.Marshal(request)
		require.NoError(t, err, "Should marshal verification update request")

		req := createAuthRequest(http.MethodPatch, "/netshield/v1/findings/finding-1/verification")
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Finding verification updated successfully", "Response should contain success message")
	})

	t.Run("invalid request body", func(t *testing.T) {
		req := createAuthRequest(http.MethodPatch, "/netshield/v1/findings/finding-1/verification")
		req.Body = io.NopCloser(bytes.NewBuffer([]byte("{invalid json}")))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for invalid JSON")
		assert.Contains(t, w.Body.String(), "invalid_request", "Response should contain invalid request error")
	})

	t.Run("missing findingId parameter", func(t *testing.T) {
		req := createAuthRequest(http.MethodPatch, "/netshield/v1/findings//verification")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for missing findingId")
		assert.Contains(t, w.Body.String(), "findingId is required", "Response should contain missing findingId error")
	})
}

// TestFindingHandler_MarkFindingsStale tests the MarkFindingsStale handler.
func TestFindingHandler_MarkFindingsStale(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/findings/mark-stale", handler.MarkFindingsStale)

	t.Run("successful mark stale", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/findings/mark-stale")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Marked", "Response should contain success message")
	})
}

// TestFindingHandler_GetFindingsByAsset tests the GetFindingsByAsset handler.
func TestFindingHandler_GetFindingsByAsset(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/assets/:assetId/findings", handler.GetFindingsByAsset)

	t.Run("successful get findings by asset", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/assets/asset-1/findings")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Findings by asset retrieved successfully", "Response should contain success message")
	})
}

// TestFindingHandler_GetFindingsByDefcon tests the GetFindingsByDefcon handler.
func TestFindingHandler_GetFindingsByDefcon(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/defcons/:defconId/findings", handler.GetFindingsByDefcon)

	t.Run("successful get findings by defcon", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/defcons/defcon-1/findings")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Findings by defcon retrieved successfully", "Response should contain success message")
	})
}

// TestFindingHandler_GetFindingsByType tests the GetFindingsByType handler.
func TestFindingHandler_GetFindingsByType(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/findings/types/:findingType", handler.GetFindingsByType)

	t.Run("successful get findings by type", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/findings/types/lateral-movement")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Findings by type retrieved successfully", "Response should contain success message")
	})
}

// TestFindingHandler_GetStaleFindings tests the GetStaleFindings handler.
func TestFindingHandler_GetStaleFindings(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &FindingHandler{
		service: getMockFindingService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/findings/stale", handler.GetStaleFindings)

	t.Run("successful get stale findings", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/findings/stale")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Stale findings retrieved successfully", "Response should contain success message")
	})
}
