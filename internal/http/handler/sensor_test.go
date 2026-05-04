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
// SensorHandler AuthZ Tests
// =============================================================================

func TestSensorHandler_ListSensors_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &SensorHandler{
		service: getMockSensorService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/sensors", handler.ListSensors)

	req := createAuthRequest("GET", "/netshield/v1/sensors")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestSensorHandler_ListSensors_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &SensorHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/sensors", handler.ListSensors)

	req := createAuthRequest("GET", "/netshield/v1/sensors")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestSensorHandler_ListSensors_AuthZError(t *testing.T) {
	cleanup := initTestAuthz(false, "", errors.New("authz error"))
	defer cleanup()

	handler := &SensorHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/sensors", handler.ListSensors)

	req := createAuthRequest("GET", "/netshield/v1/sensors")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// vp-lib authz returns a deny decision (403) for errors, not 500
	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz errors (vp-lib behavior)")
}

func TestSensorHandler_GetSensor_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &SensorHandler{
		service: getMockSensorService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/sensors/:picketId", handler.GetSensor)

	req := createAuthRequest("GET", "/netshield/v1/sensors/picket-1")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

// Note: GetSensor doesn't have AuthZ check, only AuthN, so we don't test it for AuthZ
