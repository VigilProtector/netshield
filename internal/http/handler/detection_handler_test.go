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

// TestDetectionHandler_ListDetections tests the ListDetections handler.
func TestDetectionHandler_ListDetections(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections", handler.ListDetections)

	t.Run("successful list detections", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/detections")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detections listed successfully", "Response should contain success message")
	})

	t.Run("list with filters", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/detections?limit=10&offset=0")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detections listed successfully", "Response should contain success message")
	})
}

// TestDetectionHandler_GetDetection tests the GetDetection handler.
func TestDetectionHandler_GetDetection(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections/:detectionId", handler.GetDetection)

	t.Run("successful get detection", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/detections/det-123")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detection retrieved successfully", "Response should contain success message")
	})
}

// TestDetectionHandler_CreateDetection tests the CreateDetection handler.
func TestDetectionHandler_CreateDetection(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections", handler.CreateDetection)

	t.Run("successful create detection", func(t *testing.T) {
		request := models.DetectionAPI{
			DetectionID:  "det-123",
			RuleSetID:   "rs-1",
			RuleID:      "rule-1",
			SensorID:    "picket-1",
			PicketID:    "picket-1",
			SourceIP:    "192.168.1.1",
			DestIP:      "192.168.1.2",
			DestPort:    80,
			Proto:       "tcp",
			DefconID:   "defcon-1",
			Severity:    "high",
			RawEvent:   "test event",
			Signature:  "test signature",
			Category:   "test category",
			Action:     "alert",
			Message:    "test message",
			EventType:  "alert",
			Timestamp:  "2024-01-01T00:00:00Z",
			RuleVersion: "1.0",
			Confidence:  "high",
			CreatedAt:  "2024-01-01T00:00:00Z",
			UpdatedAt:  "2024-01-01T00:00:00Z",
		}

		body, err := json.Marshal(request)
		require.NoError(t, err, "Should marshal create detection request")

		req := createAuthRequest(http.MethodPost, "/netshield/v1/detections")
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code, "Should return 201 Created")
		assert.Contains(t, w.Body.String(), "Detection created successfully", "Response should contain success message")
	})

	t.Run("invalid request body", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/detections")
		req.Body = io.NopCloser(bytes.NewBuffer([]byte("{invalid json}")))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for invalid JSON")
		assert.Contains(t, w.Body.String(), "invalid_request", "Response should contain invalid request error")
	})
}

// TestDetectionHandler_ProcessDetection tests the ProcessDetection handler.
func TestDetectionHandler_ProcessDetection(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections/:detectionId/process", handler.ProcessDetection)

	t.Run("successful process detection", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/detections/det-123/process")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detection processed successfully", "Response should contain success message")
	})

	t.Run("missing detectionId parameter", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/detections//process")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for missing detectionId")
		assert.Contains(t, w.Body.String(), "detectionId is required", "Response should contain missing detectionId error")
	})
}

// TestDetectionHandler_MarkAsProcessed tests the MarkAsProcessed handler.
func TestDetectionHandler_MarkAsProcessed(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/detections/:detectionId/mark-processed", handler.MarkAsProcessed)

	t.Run("successful mark as processed", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/detections/det-123/mark-processed")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detection marked as processed successfully", "Response should contain success message")
	})

	t.Run("missing detectionId parameter", func(t *testing.T) {
		req := createAuthRequest(http.MethodPost, "/netshield/v1/detections//mark-processed")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for missing detectionId")
		assert.Contains(t, w.Body.String(), "detectionId is required", "Response should contain missing detectionId error")
	})
}

// TestDetectionHandler_GetDetectionsBySensor tests the GetDetectionsBySensor handler.
func TestDetectionHandler_GetDetectionsBySensor(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/sensors/:picketId/detections", handler.GetDetectionsBySensor)

	t.Run("successful get detections by sensor", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/sensors/picket-1/detections")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detections by sensor retrieved successfully", "Response should contain success message")
	})
}

// TestDetectionHandler_GetDetectionsByPicket tests the GetDetectionsByPicket handler.
func TestDetectionHandler_GetDetectionsByPicket(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/pickets/:picketId/detections", handler.GetDetectionsByPicket)

	t.Run("successful get detections by picket", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/pickets/picket-1/detections")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detections by picket retrieved successfully", "Response should contain success message")
	})
}

// TestDetectionHandler_GetDetectionsByRuleSet tests the GetDetectionsByRuleSet handler.
func TestDetectionHandler_GetDetectionsByRuleSet(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets/:ruleSetId/detections", handler.GetDetectionsByRuleSet)

	t.Run("successful get detections by ruleset", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/rulesets/rs-1/detections")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detections by rule set retrieved successfully", "Response should contain success message")
	})
}

// TestDetectionHandler_GetDetectionsByRule tests the GetDetectionsByRule handler.
func TestDetectionHandler_GetDetectionsByRule(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rules/:ruleId/detections", handler.GetDetectionsByRule)

	t.Run("successful get detections by rule", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/rules/rule-1/detections")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Detections by rule retrieved successfully", "Response should contain success message")
	})
}

// TestDetectionHandler_GetUnprocessedDetections tests the GetUnprocessedDetections handler.
func TestDetectionHandler_GetUnprocessedDetections(t *testing.T) {
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &DetectionHandler{
		service: getMockDetectionService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/detections/unprocessed", handler.GetUnprocessedDetections)

	t.Run("successful get unprocessed detections", func(t *testing.T) {
		req := createAuthRequest(http.MethodGet, "/netshield/v1/detections/unprocessed")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "Unprocessed detections retrieved successfully", "Response should contain success message")
	})
}
