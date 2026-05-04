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

// TestSensorHandler_RegisterSensorViaWebhook tests the RegisterSensorViaWebhook handler.
func TestSensorHandler_RegisterSensorViaWebhook(t *testing.T) {
	// Important: Reset and init authz BEFORE creating the router or handler
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &SensorHandler{
		service: getMockSensorService(),
	}
	router := setupTestRouter()
	router.POST("/netshield/v1/sensors/webhook", handler.RegisterSensorViaWebhook)

	// Test successful registration without t.Parallel to avoid race conditions with authz
	t.Run("successful registration", func(t *testing.T) {
		// Create valid sensor API request
		sensorAPI := models.SensorAPI{
			PicketID:    "picket-1",
			DefconID:    "defcon-1",
			DefconName:  "Test Defcon",
			NodeName:    "test-node",
			Namespace:   "default",
			Status:      "active",
			Health:      "healthy",
			RuleVersion: "v1.0.0",
			LastSeen:    "2024-01-01T00:00:00Z",
			CreatedAt:   "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-01T00:00:00Z",
		}

		body, err := json.Marshal(sensorAPI)
		require.NoError(t, err, "Should marshal sensor API")

		req := createAuthRequest(http.MethodPost, "/netshield/v1/sensors/webhook")
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check response
		assert.Equal(t, http.StatusCreated, w.Code, "Should return 201 Created")
		assert.Contains(t, w.Body.String(), "Sensor registered successfully", "Response should contain success message")
	})

	t.Run("invalid request body", func(t *testing.T) {
		// Create invalid JSON
		req := createAuthRequest(http.MethodPost, "/netshield/v1/sensors/webhook")
		req.Body = io.NopCloser(bytes.NewBuffer([]byte("{invalid json}")))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check response
		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 Bad Request for invalid JSON")
		assert.Contains(t, w.Body.String(), "invalid_request", "Response should contain invalid request error")
	})
}

// TestSensorHandler_UpdateLastSeen tests the UpdateLastSeen handler.
func TestSensorHandler_UpdateLastSeen(t *testing.T) {
	// Important: Reset and init authz BEFORE creating the router or handler
	cleanup := initTestAuthz(true, "", nil)
	defer cleanup()

	handler := &SensorHandler{
		service: getMockSensorService(),
	}
	router := setupTestRouter()
	router.PUT("/netshield/v1/sensors/:picketId/lastseen", handler.UpdateLastSeen)

	t.Run("successful last seen update", func(t *testing.T) {
		req := createAuthRequest(http.MethodPut, "/netshield/v1/sensors/picket-1/lastseen")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check response
		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
		assert.Contains(t, w.Body.String(), "last seen updated", "Response should contain success message")
	})
}
