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

// NetSentinelClient provides cross-BC access to the NetSentinel Query-Fassade.
// Implements NH-CC-005: Synchrone Cross-BC-Query-Zugriffe for NetSentinel (aktuelle Flow-Metriken).
type NetSentinelClient struct {
	httpClient HTTPClient
	logger     logr.Logger
	baseURL    string
}

// NewNetSentinelClient creates a new NetSentinelClient.
func NewNetSentinelClient(baseURL string, httpClient HTTPClient, logger logr.Logger) *NetSentinelClient {
	return &NetSentinelClient{
		httpClient: httpClient,
		logger:     logger.WithName("netsentinel-client"),
		baseURL:    baseURL,
	}
}

// GetDeviceFacts retrieves live sys* snapshot for a device.
// Returns DeviceFactsResponse or error.
func (n *NetSentinelClient) GetDeviceFacts(
	ctx context.Context,
	deviceIP string,
) (*crossbc.DeviceFactsResponse, error) {
	start := time.Now()

	path := fmt.Sprintf("/api/netsentinel/v1/query/device/%s/facts", deviceIP)

	resp, err := n.httpClient.Get(ctx, path)
	n.logger.V(vplogging.LogLevelDebug).Info("NetSentinel API call",
		"method", "GetDeviceFacts",
		"deviceIP", deviceIP,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("netsentinel: failed to GET device facts: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Device not found - not an error
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netsentinel: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var result crossbc.DeviceFactsResponse
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("netsentinel: failed to decode response: %w", err)
	}

	return &result, nil
}

// GetInterfaceFacts retrieves live ifTable snapshot for a device.
// Returns InterfaceFactsResponse or error.
func (n *NetSentinelClient) GetInterfaceFacts(
	ctx context.Context,
	deviceIP string,
) (*crossbc.InterfaceFactsResponse, error) {
	start := time.Now()

	path := fmt.Sprintf("/api/netsentinel/v1/query/device/%s/interfaces", deviceIP)

	resp, err := n.httpClient.Get(ctx, path)
	n.logger.V(vplogging.LogLevelDebug).Info("NetSentinel API call",
		"method", "GetInterfaceFacts",
		"deviceIP", deviceIP,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("netsentinel: failed to GET interface facts: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Device not found - not an error
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netsentinel: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var result crossbc.InterfaceFactsResponse
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("netsentinel: failed to decode response: %w", err)
	}

	return &result, nil
}

// GetIPAddresses retrieves live ipAdEntTable snapshot for a device.
// Returns IPAddressesResponse or error.
func (n *NetSentinelClient) GetIPAddresses(
	ctx context.Context,
	deviceIP string,
) (*crossbc.IPAddressesResponse, error) {
	start := time.Now()

	path := fmt.Sprintf("/api/netsentinel/v1/query/device/%s/ipaddresses", deviceIP)

	resp, err := n.httpClient.Get(ctx, path)
	n.logger.V(vplogging.LogLevelDebug).Info("NetSentinel API call",
		"method", "GetIPAddresses",
		"deviceIP", deviceIP,
		"duration", time.Since(start))

	if err != nil {
		return nil, fmt.Errorf("netsentinel: failed to GET IP addresses: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Device not found - not an error
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netsentinel: unexpected status %d: %s",
			resp.StatusCode,
			string(resp.Body))
	}

	var result crossbc.IPAddressesResponse
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("netsentinel: failed to decode response: %w", err)
	}

	return &result, nil
}
