// Package service provides the business logic layer for NetShield.
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	vplogging "vigilprotector.io/vp-lib/logging"
)

// FlowSeekerHTTPClient implements FlowSeekerClient interface using HTTP.
// Implements NH-CC-001..004: Context-Correlation-Input-Adapter.
type FlowSeekerHTTPClient struct {
	baseURL    string
	httpClient *http.Client
	logger     logr.Logger
}

// NewFlowSeekerHTTPClient creates a new FlowSeeker HTTP client.
func NewFlowSeekerHTTPClient(baseURL string, httpClient *http.Client, logger logr.Logger) *FlowSeekerHTTPClient {
	return &FlowSeekerHTTPClient{
		baseURL:    baseURL,
		httpClient: httpClient,
		logger:     logger.WithName("flowseeker-http-client"),
	}
}

// flowSeekerFlowRequest represents a request to FlowSeeker for flow context.
type flowSeekerFlowRequest struct {
	// SourceIP is the source IP address.
	SourceIP string `json:"src_ip"`
	// DestIP is the destination IP address.
	DestIP string `json:"dst_ip"`
	// StartTime is the start of the time window.
	StartTime time.Time `json:"start_time"`
	// EndTime is the end of the time window.
	EndTime time.Time `json:"end_time"`
}

// flowSeekerFlowResponse represents a response from FlowSeeker with flow context.
type flowSeekerFlowResponse struct {
	// FlowID is the unique identifier for the flow.
	FlowID string `json:"flow_id,omitempty"`
	// SourceIP is the source IP address.
	SourceIP string `json:"src_ip,omitempty"`
	// DestIP is the destination IP address.
	DestIP string `json:"dst_ip,omitempty"`
	// Proto is the protocol.
	Proto string `json:"proto,omitempty"`
	// SourcePort is the source port.
	SourcePort int `json:"src_port,omitempty"`
	// DestPort is the destination port.
	DestPort int `json:"dst_port,omitempty"`
	// AssetID is the asset ID associated with the flow.
	AssetID string `json:"asset_id,omitempty"`
	// DefconID is the Defcon ID associated with the flow.
	DefconID string `json:"defcon_id,omitempty"`
	// Zone is the network zone.
	Zone string `json:"zone,omitempty"`
}

// GetFlowContext returns flow context for a given source/dest IP pair.
// Implements FlowSeekerClient interface (NH-CC-001..004).
func (c *FlowSeekerHTTPClient) GetFlowContext(
	ctx context.Context,
	srcIP string,
	dstIP string,
	startTime time.Time,
	endTime time.Time,
) (*FlowContext, error) {
	c.logger.V(vplogging.LogLevelDebug).Info("getting flow context",
		"srcIP", srcIP,
		"dstIP", dstIP,
		"startTime", startTime,
		"endTime", endTime)

	// If baseURL is empty, FlowSeeker is not configured
	if c.baseURL == "" {
		c.logger.V(vplogging.LogLevelDebug).Info("FlowSeeker baseURL not configured, returning nil context")
		return nil, nil
	}

	// Create request body
	request := flowSeekerFlowRequest{
		SourceIP:  srcIP,
		DestIP:    dstIP,
		StartTime: startTime,
		EndTime:   endTime,
	}

	// Marshal request
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/v1/flows/context", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Check status code
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			// Flow not found - return nil
			c.logger.V(vplogging.LogLevelDebug).Info("flow not found", "status", resp.StatusCode)

			return nil, nil
		}

		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse response
	var response flowSeekerFlowResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Convert to FlowContext
	flowCtx := &FlowContext{
		FlowID:     response.FlowID,
		SourceIP:   response.SourceIP,
		DestIP:     response.DestIP,
		Proto:      response.Proto,
		SourcePort: response.SourcePort,
		DestPort:   response.DestPort,
		AssetID:    response.AssetID,
		DefconID:   response.DefconID,
		Zone:       response.Zone,
	}

	c.logger.V(vplogging.LogLevelDebug).Info("got flow context",
		"flowId", flowCtx.FlowID,
		"assetId", flowCtx.AssetID,
		"defconId", flowCtx.DefconID)

	return flowCtx, nil
}
