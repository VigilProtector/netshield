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
// RuleSetHandler AuthZ Tests
// =============================================================================

func TestRuleSetHandler_ListRuleSets_AuthZAllowed(t *testing.T) {
	cleanup := initTestAuthz(true, "test-allowed", nil)
	defer cleanup()

	handler := &RuleSetHandler{
		service: getMockRuleSetService(),
	}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets", handler.ListRuleSets)

	req := createAuthRequest("GET", "/netshield/v1/rulesets")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should be 200 when authz allows and service works")
}

func TestRuleSetHandler_ListRuleSets_AuthZDenied(t *testing.T) {
	cleanup := initTestAuthz(false, "access denied", nil)
	defer cleanup()

	handler := &RuleSetHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets", handler.ListRuleSets)

	req := createAuthRequest("GET", "/netshield/v1/rulesets")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz denies")
}

func TestRuleSetHandler_ListRuleSets_AuthZError(t *testing.T) {
	cleanup := initTestAuthz(false, "", errors.New("authz error"))
	defer cleanup()

	handler := &RuleSetHandler{}
	router := setupTestRouter()
	router.GET("/netshield/v1/rulesets", handler.ListRuleSets)

	req := createAuthRequest("GET", "/netshield/v1/rulesets")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// vp-lib authz returns a deny decision (403) for errors, not 500
	assert.Equal(t, http.StatusForbidden, w.Code, "Should be 403 when authz errors (vp-lib behavior)")
}

// Other RuleSetHandler methods don't have AuthZ checks, so we don't test them for AuthZ
