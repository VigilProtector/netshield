// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/vp-lib/findings"
	"vigilprotector.io/vp-lib/findings/pullcursor"
	vplogging "vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// FlowSeekerConsumer handles consumption and processing of findings from FlowSeeker.
// Implements NH-LM-005: FlowSeeker-Finding-Subscription via VL-FC-002.
// Implements NH-LM-006: Event-driven Enrichment-Pipeline.
type FlowSeekerConsumer struct {
	// subscriptionClient is the pull-cursor client for FlowSeeker findings
	subscriptionClient *pullcursor.SubscriptionClient
	// detectionService is used to create detections from FlowSeeker findings
	detectionService DetectionServiceInterface
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
	logger logr.Logger,
	pollInterval time.Duration,
) *FlowSeekerConsumer {
	return &FlowSeekerConsumer{
		subscriptionClient: subscriptionClient,
		detectionService:   detectionService,
		logger:             logger.WithName("flowseeker-consumer"),
		pollInterval:       pollInterval,
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
			c.subscriptionClient.Close()

			return nil
		default:
			processed, err := c.processNextFinding(ctx)
			if err != nil {
				c.logger.Error(err, "error processing FlowSeeker finding")
				// Apply backoff on error
				select {
				case <-ctx.Done():
					c.subscriptionClient.Close()
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
					c.subscriptionClient.Close()
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

	// Acknowledge successful processing
	if ackErr := ack(ctx); ackErr != nil {
		logger.Error(ackErr, "failed to ack finding",
			"findingId", envelope.FindingID)
		// Return error so we retry
		return true, fmt.Errorf("ack failed: %w", ackErr)
	}

	logger.V(vplogging.LogLevelInfo).Info("processed FlowSeeker finding",
		"findingId", envelope.FindingID,
		"detectionId", detection.DetectionID)

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

	// TODO: NH-LM-006: Add enrichment from FlowSeeker flow context
	// This would require calling FlowSeekerClient.GetFlowContext with the
	// source/dest IPs from the finding to get additional context like
	// AssetID, DefconID, Zone, etc.

	// TODO: NH-CC-005: Add enrichment from Aegis for asset information
	// This would require calling Aegis API to get detailed asset information
	// for the source/destination IPs in the finding

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

// Close closes the underlying subscription client.
func (c *FlowSeekerConsumer) Close() error {
	return c.subscriptionClient.Close()
}
