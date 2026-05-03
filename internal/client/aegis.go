// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/crossbc"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// ErrAssetNotFound is returned when an asset does not exist in Aegis.
var ErrAssetNotFound = errors.New("asset not found in aegis")

// AegisClient provides cross-BC access to the Aegis asset service.
// Implements NH-CC-005: Synchrone Cross-BC-Query-Zugriffe for Aegis (Asset-Identity, Criticality).
type AegisClient struct {
	httpClient HTTPClient
	logger     logr.Logger
	baseURL    string
}

// NewAegisClient creates a new AegisClient.
func NewAegisClient(baseURL string, httpClient HTTPClient, logger logr.Logger) *AegisClient {
	return &AegisClient{
		httpClient: httpClient,
		logger:     logger.WithName("aegis-client"),
		baseURL:    baseURL,
	}
}

// GetAsset retrieves an asset by ID from the Aegis API.
func (a *AegisClient) GetAsset(
	ctx context.Context,
	assetID string,
) (*crossbc.AegisAssetDetail, error) {
	start := time.Now()

	path := "/api/aegis/v1/assets/" + assetID

	resp, err := a.httpClient.Get(ctx, path)
	a.logger.V(vplogging.LogLevelDebug).Info("Aegis API call",
		"method", "GetAsset",
		"assetId", assetID,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("aegis: failed to GET asset: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrAssetNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aegis: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var envelope struct {
		Data crossbc.AegisAssetDetail `json:"data"`
	}

	err = json.Unmarshal(resp.Body, &envelope)
	if err != nil {
		return nil, fmt.Errorf("aegis: failed to decode response: %w", err)
	}

	return &envelope.Data, nil
}

// GetAssetByIP retrieves an asset by its IP address from the Aegis API.
func (a *AegisClient) GetAssetByIP(
	ctx context.Context,
	ipAddress string,
) (*crossbc.AegisAssetDetail, error) {
	start := time.Now()

	path := fmt.Sprintf("/api/aegis/v1/assets/by-ip/%s", ipAddress)

	resp, err := a.httpClient.Get(ctx, path)
	a.logger.V(vplogging.LogLevelDebug).Info("Aegis API call",
		"method", "GetAssetByIP",
		"ipAddress", ipAddress,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("aegis: failed to GET asset by IP: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrAssetNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aegis: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var envelope struct {
		Data crossbc.AegisAssetDetail `json:"data"`
	}

	err = json.Unmarshal(resp.Body, &envelope)
	if err != nil {
		return nil, fmt.Errorf("aegis: failed to decode response: %w", err)
	}

	return &envelope.Data, nil
}
