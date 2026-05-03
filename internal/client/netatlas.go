// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/crossbc"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// NetAtlasClient provides cross-BC access to the NetAtlas topology service.
// Implements NH-CC-005: Synchrone Cross-BC-Query-Zugriffe for NetAtlas (Zone, Topologie).
type NetAtlasClient struct {
	httpClient HTTPClient
	logger     logr.Logger
	baseURL    string
}

// NewNetAtlasClient creates a new NetAtlasClient.
func NewNetAtlasClient(baseURL string, httpClient HTTPClient, logger logr.Logger) *NetAtlasClient {
	return &NetAtlasClient{
		httpClient: httpClient,
		logger:     logger.WithName("netatlas-client"),
		baseURL:    baseURL,
	}
}

// GetTopologyPath retrieves the shortest path between two assets.
// Returns TopologyPathAPI or error.
func (n *NetAtlasClient) GetTopologyPath(
	ctx context.Context,
	fromAssetID string,
	toAssetID string,
) (*crossbc.TopologyPathAPI, error) {
	start := time.Now()

	path := fmt.Sprintf("/api/netatlas/v1/topology/path/%s/%s", fromAssetID, toAssetID)

	resp, err := n.httpClient.Get(ctx, path)
	n.logger.V(vplogging.LogLevelDebug).Info("NetAtlas API call",
		"method", "GetTopologyPath",
		"fromAssetID", fromAssetID,
		"toAssetID", toAssetID,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("netatlas: failed to GET topology path: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Path not found - not an error
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netatlas: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var result crossbc.TopologyPathAPI
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("netatlas: failed to decode response: %w", err)
	}

	return &result, nil
}

// GetZoneForAsset retrieves the zone information for a given asset.
// Returns the zone AssetID and name, or error.
func (n *NetAtlasClient) GetZoneForAsset(
	ctx context.Context,
	assetID string,
) (*crossbc.TopologyZoneAPI, error) {
	start := time.Now()

	path := fmt.Sprintf("/api/netatlas/v1/topology/zones/for-asset/%s", assetID)

	resp, err := n.httpClient.Get(ctx, path)
	n.logger.V(vplogging.LogLevelDebug).Info("NetAtlas API call",
		"method", "GetZoneForAsset",
		"assetID", assetID,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("netatlas: failed to GET zone for asset: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Zone not found - not an error
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netatlas: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var result crossbc.TopologyZoneAPI
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("netatlas: failed to decode response: %w", err)
	}

	return &result, nil
}

// GetLatestSnapshot retrieves the latest topology snapshot.
// Returns TopologySnapshotAPI or error.
func (n *NetAtlasClient) GetLatestSnapshot(
	ctx context.Context,
) (*crossbc.TopologySnapshotAPI, error) {
	start := time.Now()

	path := "/api/netatlas/v1/topology/snapshot/latest"

	resp, err := n.httpClient.Get(ctx, path)
	n.logger.V(vplogging.LogLevelDebug).Info("NetAtlas API call",
		"method", "GetLatestSnapshot",
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("netatlas: failed to GET latest snapshot: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Snapshot not found - not an error
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netatlas: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var result crossbc.TopologySnapshotAPI
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("netatlas: failed to decode response: %w", err)
	}

	return &result, nil
}
