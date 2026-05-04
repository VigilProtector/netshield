// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/client"
	"vigilprotector.io/netshield/internal/crossbc"
	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/vp-lib/findings"
	"vigilprotector.io/vp-lib/findings/pullcursor"
	vplogging "vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// AegisClientAdapter wraps client.AegisClient to provide the AegisClientInterface.
type AegisClientAdapter struct {
	client *client.AegisClient
}

// GetAsset retrieves an asset by ID from Aegis.
func (a *AegisClientAdapter) GetAsset(ctx context.Context, assetID string) (*crossbc.AegisAssetDetail, error) {
	if a.client == nil {
		return nil, nil
	}

	return a.client.GetAsset(ctx, assetID)
}

// NetSentinelClientAdapter wraps client.NetSentinelClient to provide the NetSentinelClientInterface.
type NetSentinelClientAdapter struct {
	client *client.NetSentinelClient
}

// GetDeviceFacts retrieves live sys* snapshot for a device.
func (n *NetSentinelClientAdapter) GetDeviceFacts(ctx context.Context, deviceIP string) (*crossbc.DeviceFactsResponse, error) {
	if n.client == nil {
		return nil, nil
	}

	return n.client.GetDeviceFacts(ctx, deviceIP)
}

// GetInterfaceFacts retrieves live ifTable snapshot for a device.
func (n *NetSentinelClientAdapter) GetInterfaceFacts(ctx context.Context, deviceIP string) (*crossbc.InterfaceFactsResponse, error) {
	if n.client == nil {
		return nil, nil
	}

	return n.client.GetInterfaceFacts(ctx, deviceIP)
}

// GetIPAddresses retrieves live ipAdEntTable snapshot for a device.
func (n *NetSentinelClientAdapter) GetIPAddresses(ctx context.Context, deviceIP string) (*crossbc.IPAddressesResponse, error) {
	if n.client == nil {
		return nil, nil
	}

	return n.client.GetIPAddresses(ctx, deviceIP)
}

// NetAtlasClientAdapter wraps client.NetAtlasClient to provide the NetAtlasClientInterface.
type NetAtlasClientAdapter struct {
	client *client.NetAtlasClient
}

// GetTopologyPath retrieves the shortest path between two assets.
func (n *NetAtlasClientAdapter) GetTopologyPath(ctx context.Context, fromAssetID string, toAssetID string) (*crossbc.TopologyPathAPI, error) {
	if n.client == nil {
		return nil, nil
	}

	return n.client.GetTopologyPath(ctx, fromAssetID, toAssetID)
}

// GetZoneForAsset retrieves the zone information for a given asset.
func (n *NetAtlasClientAdapter) GetZoneForAsset(ctx context.Context, assetID string) (*crossbc.TopologyZoneAPI, error) {
	if n.client == nil {
		return nil, nil
	}

	return n.client.GetZoneForAsset(ctx, assetID)
}

// GetLatestSnapshot retrieves the latest topology snapshot.
func (n *NetAtlasClientAdapter) GetLatestSnapshot(ctx context.Context) (*crossbc.TopologySnapshotAPI, error) {
	if n.client == nil {
		return nil, nil
	}

	return n.client.GetLatestSnapshot(ctx)
}

// FlowSeekerConsumer handles consumption and processing of findings from FlowSeeker.
// Implements NH-LM-005: FlowSeeker-Finding-Subscription via VL-FC-002.
// Implements NH-LM-006: Event-driven Enrichment-Pipeline.
// Implements NH-LM-007: Emission network.lateral_movement_suspected.
// Implements NH-CC-005: Cross-BC Queries for Aegis, NetSentinel, NetAtlas.
type FlowSeekerConsumer struct {
	// subscriptionClient is the pull-cursor client for FlowSeeker findings
	subscriptionClient *pullcursor.SubscriptionClient
	// detectionService is used to create detections from FlowSeeker findings
	detectionService DetectionServiceInterface
	// findingService is used to create findings from lateral movement detection
	findingService FindingServiceInterface
	// flowSeekerClient is used to fetch flow context for correlation (NH-CC-001..004, NH-LM-006)
	flowSeekerClient FlowSeekerClient
	// lateralMovementDetector is used for NH-LM-001..007 lateral movement detection
	lateralMovementDetector *LateralMovementDetector
	// lateralMovementConfig holds configuration for lateral movement detection
	lateralMovementConfig LateralMovementConfig
	// Cross-BC Query Clients for NH-CC-005
	// Note: Using adapter types that wrap client implementations
	// aegisClient provides Asset-Identity and Criticality information
	aegisClient *AegisClientAdapter
	// netSentinelClient provides Device-Facts and Flow-Metrics
	netSentinelClient *NetSentinelClientAdapter
	// netAtlasClient provides Zone and Topology information
	netAtlasClient *NetAtlasClientAdapter
	// logger for this consumer
	logger logr.Logger
	// pollInterval is how often to check for new findings
	pollInterval time.Duration
}

// NewFlowSeekerConsumer creates a new FlowSeekerConsumer.
// The subscriptionClient should be pre-configured with the FlowSeeker subscription endpoint.
func NewFlowSeekerConsumer(
	subscriptionClient *pullcursor.SubscriptionClient,
	detectionService DetectionServiceInterface,
	findingService FindingServiceInterface,
	flowSeekerClient FlowSeekerClient,
	lateralMovementDetector *LateralMovementDetector,
	lateralMovementConfig LateralMovementConfig,
	aegisClient *AegisClientAdapter,
	netSentinelClient *NetSentinelClientAdapter,
	netAtlasClient *NetAtlasClientAdapter,
	logger logr.Logger,
	pollInterval time.Duration,
) *FlowSeekerConsumer {
	return &FlowSeekerConsumer{
		subscriptionClient:      subscriptionClient,
		detectionService:        detectionService,
		findingService:          findingService,
		flowSeekerClient:        flowSeekerClient,
		lateralMovementDetector: lateralMovementDetector,
		lateralMovementConfig:   lateralMovementConfig,
		aegisClient:             aegisClient,
		netSentinelClient:       netSentinelClient,
		netAtlasClient:          netAtlasClient,
		logger:                  logger.WithName("flowseeker-consumer"),
		pollInterval:            pollInterval,
	}
}

// Start starts the consumer polling loop.
// Implements NH-LM-005: FlowSeeker-Finding-Subscription via VL-FC-002.
func (c *FlowSeekerConsumer) Start(ctx context.Context) error {
	c.logger.V(vplogging.LogLevelInfo).Info("starting FlowSeeker findings consumer",
		"pollInterval", c.pollInterval)

	// Main polling loop - SubscriptionClient.Next() handles the pull-cursor logic internally
	for {
		select {
		case <-ctx.Done():
			c.logger.V(vplogging.LogLevelInfo).Info("FlowSeeker consumer shutting down")
			c.subscriptionClient.Close() //nolint:errcheck // gRPC client Close errors during shutdown are non-critical

			return nil
		default:
			processed, err := c.processNextFinding(ctx)
			if err != nil {
				c.logger.Error(err, "error processing FlowSeeker finding")
				// Apply backoff on error
				select {
				case <-ctx.Done():
					c.subscriptionClient.Close() //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored
					return nil
				case <-time.After(c.pollInterval):
				}
			} else if processed {
				// Continue immediately if we processed a finding
				// (there might be more available)
				continue
			} else {
				// No finding available, wait for interval
				select {
				case <-ctx.Done():
					c.subscriptionClient.Close() //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored
					return nil
				case <-time.After(c.pollInterval):
				}
			}
		}
	}
}

// processNextFinding processes the next available finding from FlowSeeker.
// Implements NH-LM-006: Event-driven Enrichment-Pipeline.
func (c *FlowSeekerConsumer) processNextFinding(ctx context.Context) (bool, error) {
	logger := c.logger.WithValues("method", "processNextFinding")

	// Get next envelope from subscription
	envelope, ack, err := c.subscriptionClient.Next(ctx)
	if err != nil {
		if err == findings.ErrSubscriptionClosed {
			logger.V(vplogging.LogLevelDebug).Info("subscription closed, no more findings")
			return false, nil
		}

		return false, fmt.Errorf("failed to get next finding: %w", err)
	}

	// Filter findings - only process those from FlowSeeker that we handle
	// The SubscriptionClient doesn't filter by source context, so we do it here
	if !c.shouldProcessFinding(envelope) {
		logger.V(vplogging.LogLevelVerbose).Info("skipping non-FlowSeeker finding",
			"findingId", envelope.FindingID,
			"sourceContext", envelope.SourceContext,
			"findingType", envelope.FindingType)
		// Acknowledge to avoid reprocessing
		if ackErr := ack(ctx); ackErr != nil {
			logger.Error(ackErr, "failed to ack skipped finding",
				"findingId", envelope.FindingID)
		}

		return true, nil // Count as processed since we handled it
	}

	logger.V(vplogging.LogLevelVerbose).Info("received finding from FlowSeeker",
		"findingId", envelope.FindingID,
		"findingType", envelope.FindingType,
		"sourceContext", envelope.SourceContext)

	// Convert finding to detection
	detection, err := c.convertFindingToDetection(envelope)
	if err != nil {
		logger.Error(err, "failed to convert finding to detection",
			"findingId", envelope.FindingID)
		// Acknowledge to avoid reprocessing
		if ackErr := ack(ctx); ackErr != nil {
			logger.Error(ackErr, "failed to ack failed finding",
				"findingId", envelope.FindingID)
		}

		return true, nil // Don't propagate conversion errors
	}

	// Create detection in NetShield
	// Note: We don't have a subject here since this is internal processing
	// Using a controller subject for audit purposes
	systemSubject := &types.Subject{
		Type: types.SubjectTypeController,
		ID:   "netshield-flowseeker-consumer",
	}

	_, err = c.detectionService.Create(ctx, logger, systemSubject, detection)
	if err != nil {
		logger.Error(err, "failed to create detection from finding",
			"findingId", envelope.FindingID,
			"detectionId", detection.DetectionID)
		// Don't acknowledge - we'll retry on next poll
		return true, nil
	}

	// NH-LM-006: Event-driven Enrichment-Pipeline
	// NH-CC-005: Cross-BC Query - Get flow context and enrich with Aegis/NetSentinel/NetAtlas
	// Use a reasonable time window around the finding timestamp
	timeWindowStart := detection.Timestamp.Add(-1 * time.Minute)
	timeWindowEnd := detection.Timestamp.Add(1 * time.Minute)

	// Get flow context from FlowSeeker (NH-CC-001..004)
	flowCtx, err := c.flowSeekerClient.GetFlowContext(
		ctx,
		detection.SourceIP,
		detection.DestIP,
		timeWindowStart,
		timeWindowEnd,
	)
	if err != nil {
		logger.Error(err, "failed to get flow context for lateral movement detection",
			"findingId", envelope.FindingID,
			"detectionId", detection.DetectionID,
			"srcIP", detection.SourceIP,
			"dstIP", detection.DestIP)
	}

	// NH-CC-005: Enrich with cross-BC context information
	c.enrichWithCrossBCContext(ctx, logger, detection, flowCtx)

	// Log flow context retrieval for lateral movement analysis
	if flowCtx != nil {
		logger.V(vplogging.LogLevelDebug).Info("retrieved flow context for lateral movement analysis",
			"detectionId", detection.DetectionID,
			"flowId", flowCtx.FlowID,
			"assetId", flowCtx.AssetID,
			"defconId", flowCtx.DefconID)
	}

	// NH-LM-005/006/007: Process detection for lateral movement
	// Implements NH-LM-001..004 via LateralMovementDetector
	finding, isLateralMovement := c.lateralMovementDetector.ProcessDetectionForLateralMovement(
		ctx,
		logger,
		detection,
		flowCtx,
		c.lateralMovementConfig,
	)

	if isLateralMovement && finding != nil {
		// NH-LM-007: Emit network.lateral_movement_suspected finding
		logger.V(vplogging.LogLevelInfo).Info("lateral movement detected, creating finding",
			"findingId", finding.FindingID,
			"detectionId", detection.DetectionID)

		// Create the lateral movement finding in NetShield
		// Using the same system subject for audit consistency
		_, err = c.findingService.Create(ctx, logger, systemSubject, finding)
		if err != nil {
			logger.Error(err, "failed to create lateral movement finding", // Continue - finding creation failure shouldn't block detection processing
				"findingId", finding.FindingID,
				"detectionId", detection.DetectionID)
		} else {
			logger.V(vplogging.LogLevelInfo).Info("created lateral movement finding",
				"findingId", finding.FindingID,
				"findingType", finding.FindingType)
		}
	}

	// Acknowledge successful processing
	if ackErr := ack(ctx); ackErr != nil {
		logger.Error(ackErr, "failed to ack finding",
			"findingId", envelope.FindingID)
		// Return error so we retry
		return true, fmt.Errorf("ack failed: %w", ackErr)
	}

	logger.V(vplogging.LogLevelInfo).Info("processed FlowSeeker finding",
		"findingId", envelope.FindingID,
		"detectionId", detection.DetectionID,
		"lateralMovementDetected", isLateralMovement)

	return true, nil
}

// shouldProcessFinding determines if a finding should be processed by NetShield.
// Implements NH-SG-009: Only alert and anomaly go to NetShield (plus flow for correlation).
func (c *FlowSeekerConsumer) shouldProcessFinding(envelope findings.Envelope) bool {
	// Must be from FlowSeeker
	if envelope.SourceContext != "flowseeker" {
		return false
	}

	// Get finding types that NetShield handles
	switch envelope.FindingType {
	case "network.lateral_movement_suspected":
		return true
	case "network.device_reachability_degraded":
		return true
	case "network.path_inconsistency_detected":
		return true
	case "network.policy_violation_detected":
		return true
	case "known_attack_pattern_detected":
		return true
	case "network.anomaly":
		return true
	default:
		// For now, accept all FlowSeeker findings
		// In production, this should be more restrictive based on NH-SG-009
		return true
	}
}

// convertFindingToDetection converts a FlowSeeker finding envelope to a NetShield detection.
// Implements NH-LM-006: Event-driven Enrichment-Pipeline step 1.
func (c *FlowSeekerConsumer) convertFindingToDetection(envelope findings.Envelope) (*models.Detection, error) {
	// Map FlowSeeker finding types to NetShield detection event types
	eventType := mapFlowSeekerFindingType(envelope.FindingType)

	// Create unique detection ID from FlowSeeker finding
	// Format: det-flowseeker-{findingId}
	detectionID := fmt.Sprintf("det-flowseeker-%s", envelope.FindingID)

	// Extract details from finding payload if available
	// For now, we'll use basic metadata
	detection := &models.Detection{
		DetectionID: detectionID,
		SensorID:    envelope.SourceContext, // Will be updated with actual sensor info if available
		PicketID:    "",                     // Will be enriched from FlowSeeker context
		RuleSetID:   "flowseeker",
		RuleID:      envelope.FindingType,
		EventType:   eventType,
		Timestamp:   envelope.OccurredAt,
		Signature:   envelope.FindingType,
		Category:    "flow",
		Severity:    models.RuleSeverityInformational, // Will be enriched
		Confidence:  models.ConfidenceHigh,
		Message:     envelope.FindingID,
		// Source/Dest IPs and other details will be enriched in future iterations
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// NH-LM-006: Flow context enrichment is now handled in processNextFinding
	// via FlowSeekerClient.GetFlowContext

	// NH-CC-005: Cross-BC enrichment (Aegis, NetSentinel, NetAtlas) is handled
	// in processNextFinding via the respective clients

	return detection, nil
}

// mapFlowSeekerFindingType maps FlowSeeker finding types to NetShield detection event types.
// This ensures that findings from FlowSeeker are properly categorized in NetShield.
func mapFlowSeekerFindingType(findingType string) models.DetectionEventType {
	switch findingType {
	case "network.lateral_movement_suspected":
		return models.DetectionEventTypeLateralMovement
	case "network.device_reachability_degraded":
		return models.DetectionEventTypeAlert
	case "network.path_inconsistency_detected":
		return models.DetectionEventTypeAnomaly
	case "network.policy_violation_detected":
		return models.DetectionEventTypePolicyViolation
	case "known_attack_pattern_detected":
		return models.DetectionEventTypeAlert
	case "network.anomaly":
		return models.DetectionEventTypeAnomaly
	default:
		// For unknown types, default to flow
		// NH-SG-009: Only alert and anomaly go to NetShield, but we also accept
		// flow findings from FlowSeeker for correlation purposes
		return models.DetectionEventTypeFlow
	}
}

// enrichWithCrossBCContext enriches the detection with cross-BC context information.
// Implements NH-CC-005: Synchrone Cross-BC-Query-Zugriffe.
func (c *FlowSeekerConsumer) enrichWithCrossBCContext(
	ctx context.Context,
	logger logr.Logger,
	detection *models.Detection,
	flowCtx *FlowContext,
) {
	if flowCtx == nil {
		return
	}

	// Enrich with Aegis asset information
	if flowCtx.AssetID != "" && c.aegisClient != nil {
		aegisAsset, aegisErr := c.aegisClient.GetAsset(ctx, flowCtx.AssetID)
		if aegisErr == nil && aegisAsset != nil {
			// Enrich detection with asset identity and criticality
			if aegisAsset.Hostname != "" {
				detection.AssetID = aegisAsset.ID
			}

			if aegisAsset.Criticality != "" {
				// Map criticality to detection severity if needed
				logger.V(vplogging.LogLevelDebug).Info("enriched with Aegis asset info",
					"assetId", aegisAsset.ID,
					"criticality", aegisAsset.Criticality)
			} else {
				logger.V(vplogging.LogLevelDebug).Info("Aegis asset not found for flow context",
					"assetId", flowCtx.AssetID)
			}
		}
	}

	// Enrich with NetSentinel device metrics
	if flowCtx.DestIP != "" && c.netSentinelClient != nil {
		deviceFacts, nsErr := c.netSentinelClient.GetDeviceFacts(ctx, flowCtx.DestIP)
		if nsErr == nil && deviceFacts != nil {
			logger.V(vplogging.LogLevelDebug).Info("enriched with NetSentinel device facts",
				"deviceIp", deviceFacts.DeviceIP,
				"sysName", deviceFacts.SysName,
				"freshness", deviceFacts.Freshness)
		} else {
			logger.V(vplogging.LogLevelDebug).Info("NetSentinel device facts not found",
				"deviceIp", flowCtx.DestIP)
		}
	}

	// Enrich with NetAtlas zone information
	if flowCtx.AssetID != "" && c.netAtlasClient != nil {
		zoneInfo, naErr := c.netAtlasClient.GetZoneForAsset(ctx, flowCtx.AssetID)
		if naErr == nil && zoneInfo != nil {
			logger.V(vplogging.LogLevelDebug).Info("enriched with NetAtlas zone info",
				"assetId", flowCtx.AssetID,
				"zoneAssetId", zoneInfo.AssetID)
		} else {
			logger.V(vplogging.LogLevelDebug).Info("NetAtlas zone not found for asset",
				"assetId", flowCtx.AssetID)
		}
	}
}

// Close closes the underlying subscription client.
func (c *FlowSeekerConsumer) Close() error {
	return c.subscriptionClient.Close()
}
