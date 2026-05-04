// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestFlowSeekerHTTPClient_GetFlowContext_NoBaseURL(t *testing.T) {
	logger := zap.New(zap.UseDevMode(true))
	client := &http.Client{}

	httpClient := NewFlowSeekerHTTPClient("", client, logger)

	ctx := context.Background()
	flowCtx, err := httpClient.GetFlowContext(ctx, "192.168.1.1", "192.168.1.2", time.Now(), time.Now())

	assert.NoError(t, err, "Should not return error when baseURL is empty")
	assert.Nil(t, flowCtx, "Should return nil flow context when baseURL is empty")
}

func TestFlowSeekerHTTPClient_GetFlowContext_Success(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodPost, r.Method, "Should use POST method")
		assert.Equal(t, "/v1/flows/context", r.URL.Path, "Should use correct path")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"), "Should set Content-Type header")
		assert.Equal(t, "application/json", r.Header.Get("Accept"), "Should set Accept header")

		// Read and parse request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err, "Should read request body")

		var request flowSeekerFlowRequest
		err = json.Unmarshal(body, &request)
		require.NoError(t, err, "Should unmarshal request body")

		assert.Equal(t, "192.168.1.1", request.SourceIP, "SourceIP should match")
		assert.Equal(t, "192.168.1.2", request.DestIP, "DestIP should match")

		// Return mock response
		response := flowSeekerFlowResponse{
			FlowID:     "flow-123",
			SourceIP:   "192.168.1.1",
			DestIP:     "192.168.1.2",
			Proto:      "tcp",
			SourcePort: 12345,
			DestPort:   80,
			AssetID:    "asset-1",
			DefconID:   "defcon-1",
			Zone:       "internal",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	logger := zap.New(zap.UseDevMode(true))
	httpClient := NewFlowSeekerHTTPClient(server.URL, &http.Client{}, logger)

	ctx := context.Background()
	startTime := time.Now().Add(-5 * time.Minute)
	endTime := time.Now()

	flowCtx, err := httpClient.GetFlowContext(ctx, "192.168.1.1", "192.168.1.2", startTime, endTime)

	assert.NoError(t, err, "Should not return error")
	assert.NotNil(t, flowCtx, "Should return flow context")
	assert.Equal(t, "flow-123", flowCtx.FlowID, "FlowID should match")
	assert.Equal(t, "192.168.1.1", flowCtx.SourceIP, "SourceIP should match")
	assert.Equal(t, "192.168.1.2", flowCtx.DestIP, "DestIP should match")
	assert.Equal(t, "tcp", flowCtx.Proto, "Proto should match")
	assert.Equal(t, 12345, flowCtx.SourcePort, "SourcePort should match")
	assert.Equal(t, 80, flowCtx.DestPort, "DestPort should match")
	assert.Equal(t, "asset-1", flowCtx.AssetID, "AssetID should match")
	assert.Equal(t, "defcon-1", flowCtx.DefconID, "DefconID should match")
	assert.Equal(t, "internal", flowCtx.Zone, "Zone should match")
}

func TestFlowSeekerHTTPClient_GetFlowContext_NotFound(t *testing.T) {
	// Create a test server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := zap.New(zap.UseDevMode(true))
	httpClient := NewFlowSeekerHTTPClient(server.URL, &http.Client{}, logger)

	ctx := context.Background()
	startTime := time.Now().Add(-5 * time.Minute)
	endTime := time.Now()

	flowCtx, err := httpClient.GetFlowContext(ctx, "192.168.1.1", "192.168.1.2", startTime, endTime)

	assert.NoError(t, err, "Should not return error for 404")
	assert.Nil(t, flowCtx, "Should return nil flow context for 404")
}

func TestFlowSeekerHTTPClient_GetFlowContext_InternalServerError(t *testing.T) {
	// Create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger := zap.New(zap.UseDevMode(true))
	httpClient := NewFlowSeekerHTTPClient(server.URL, &http.Client{}, logger)

	ctx := context.Background()
	startTime := time.Now().Add(-5 * time.Minute)
	endTime := time.Now()

	flowCtx, err := httpClient.GetFlowContext(ctx, "192.168.1.1", "192.168.1.2", startTime, endTime)

	assert.Error(t, err, "Should return error for 500")
	assert.Contains(t, err.Error(), "unexpected status code: 500", "Error should contain status code")
	assert.Nil(t, flowCtx, "Should return nil flow context for error")
}

func TestFlowSeekerHTTPClient_GetFlowContext_MalformedResponse(t *testing.T) {
	// Create a test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid json}"))
	}))
	defer server.Close()

	logger := zap.New(zap.UseDevMode(true))
	httpClient := NewFlowSeekerHTTPClient(server.URL, &http.Client{}, logger)

	ctx := context.Background()
	startTime := time.Now().Add(-5 * time.Minute)
	endTime := time.Now()

	flowCtx, err := httpClient.GetFlowContext(ctx, "192.168.1.1", "192.168.1.2", startTime, endTime)

	assert.Error(t, err, "Should return error for malformed JSON")
	assert.Contains(t, err.Error(), "failed to parse response", "Error should indicate parse failure")
	assert.Nil(t, flowCtx, "Should return nil flow context for error")
}

func TestFlowSeekerHTTPClient_GetFlowContext_EmptyResponse(t *testing.T) {
	// Create a test server that returns empty body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Empty body
	}))
	defer server.Close()

	logger := zap.New(zap.UseDevMode(true))
	httpClient := NewFlowSeekerHTTPClient(server.URL, &http.Client{}, logger)

	ctx := context.Background()
	startTime := time.Now().Add(-5 * time.Minute)
	endTime := time.Now()

	flowCtx, err := httpClient.GetFlowContext(ctx, "192.168.1.1", "192.168.1.2", startTime, endTime)

	assert.Error(t, err, "Should return error for empty response")
	assert.Nil(t, flowCtx, "Should return nil flow context for error")
}

func TestFlowSeekerHTTPClient_GetFlowContext_NetworkError(t *testing.T) {
	// Use an invalid URL to trigger network error
	logger := zap.New(zap.UseDevMode(true))
	httpClient := NewFlowSeekerHTTPClient("http://invalid-host-that-does-not-exist:9999", &http.Client{}, logger)

	ctx := context.Background()
	startTime := time.Now().Add(-5 * time.Minute)
	endTime := time.Now()

	// Set a short timeout to avoid long wait
	httpClient.httpClient.Timeout = 1 * time.Millisecond

	flowCtx, err := httpClient.GetFlowContext(ctx, "192.168.1.1", "192.168.1.2", startTime, endTime)

	assert.Error(t, err, "Should return error for network failure")
	assert.Contains(t, err.Error(), "failed to execute request", "Error should indicate request failure")
	assert.Nil(t, flowCtx, "Should return nil flow context for error")
}
