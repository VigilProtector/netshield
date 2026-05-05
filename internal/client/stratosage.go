// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/vp-lib/logging"
)

// Baseline represents a StratoSage baseline for a given scope and feature set.
// SS-BP-004: Consumer expects this structure from StratoSage baseline API.
type Baseline struct {
	ID           string                 `json:"id"`
	ScopeRef     string                 `json:"scopeRef"`
	FeatureSet   string                 `json:"featureSet"`
	Stats        map[string]float64     `json:"stats"`
	ModelVersion string                 `json:"modelVersion"`
	ValidFrom    time.Time              `json:"validFrom"`
	ValidUntil   *time.Time             `json:"validUntil,omitempty"`
	Metadata     map[string]string      `json:"metadata,omitempty"`
}

// BaselineQueryResponse is the response from StratoSage baseline query API.
type BaselineQueryResponse struct {
	Baseline *Baseline `json:"baseline,omitempty"`
	Error   string     `json:"error,omitempty"`
}

// StratoSageClient provides cross-BC access to StratoSage baseline data.
// Implements SS-BP-004: Cross-BC consumer for StratoSage baselines.
type StratoSageClient struct {
	httpClient HTTPClient
	logger    logr.Logger
	baseURL   string
}

// NewStratoSageClient creates a new StratoSageClient.
// The httpClient parameter should implement the HTTPClient interface (not *http.Client).
// Use NewHTTPClientWithTimeout to create a properly configured client.
func NewStratoSageClient(baseURL string, httpClient HTTPClient, logger logr.Logger) *StratoSageClient {
	return &StratoSageClient{
		httpClient: httpClient,
		logger:    logger.WithName("stratosage-client"),
		baseURL:   baseURL,
	}
}

// GetBaseline retrieves the baseline for a given scope and feature set.
// SS-BP-004: Replaces local heuristic thresholds with StratoSage baseline evaluation.
func (s *StratoSageClient) GetBaseline(
	ctx context.Context,
	scopeRef string,
	featureSet string,
) (*Baseline, error) {
	start := time.Now()

	// Encode scopeRef and featureSet for URL
	path := fmt.Sprintf("/stratosage/v1/baselines/query?scopeRef=%s&featureSet=%s",
		scopeRef, featureSet)

	resp, err := s.httpClient.Get(ctx, path)
	s.logger.V(logging.LogLevelDebug).Info("StratoSage API call",
		"method", "GetBaseline",
		"scopeRef", scopeRef,
		"featureSet", featureSet,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("failed to query StratoSage baseline: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("StratoSage API returned status %d for scope %s",
			resp.StatusCode, scopeRef)
	}

	var response BaselineQueryResponse
	if err := json.Unmarshal(resp.Body, &response); err != nil {
		return nil, fmt.Errorf("failed to decode StratoSage baseline response: %w", err)
	}

	if response.Error != "" {
		return nil, fmt.Errorf("StratoSage returned error: %s", response.Error)
	}

	if response.Baseline == nil {
		// No baseline found for this scope/feature set
		s.logger.V(logging.LogLevelVerbose).Info("No baseline found",
			"scopeRef", scopeRef, "featureSet", featureSet)
		return nil, nil
	}

	return response.Baseline, nil
}

// GetBaselinesForScope retrieves all baselines for a given scope.
// Useful for bulk baseline fetching.
func (s *StratoSageClient) GetBaselinesForScope(
	ctx context.Context,
	scopeRef string,
) ([]*Baseline, error) {
	start := time.Now()

	path := fmt.Sprintf("/stratosage/v1/baselines?scopeRef=%s", scopeRef)

	resp, err := s.httpClient.Get(ctx, path)
	s.logger.V(logging.LogLevelDebug).Info("StratoSage API call",
		"method", "GetBaselinesForScope",
		"scopeRef", scopeRef,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("failed to query StratoSage baselines: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("StratoSage API returned status %d for scope %s",
			resp.StatusCode, scopeRef)
	}

	var baselines []*Baseline
	if err := json.Unmarshal(resp.Body, &baselines); err != nil {
		return nil, fmt.Errorf("failed to decode StratoSage baselines response: %w", err)
	}

	return baselines, nil
}

// BaselineProvider is an interface for accessing StratoSage baselines.
// This allows for dependency injection and testing.
// SS-BP-004: Defines the contract for baseline access.
type BaselineProvider interface {
	// GetBaseline retrieves a baseline for a given scope and feature set.
	GetBaseline(ctx context.Context, scopeRef, featureSet string) (*Baseline, error)
	// GetBaselinesForScope retrieves all baselines for a given scope.
	GetBaselinesForScope(ctx context.Context, scopeRef string) ([]*Baseline, error)
}

// NewBaselineProvider creates a BaselineProvider that wraps StratoSageClient.
// This is a convenience function for creating a provider from configuration.
func NewBaselineProvider(baseURL string, httpClient HTTPClient, logger logr.Logger) BaselineProvider {
	return NewStratoSageClient(baseURL, httpClient, logger)
}
