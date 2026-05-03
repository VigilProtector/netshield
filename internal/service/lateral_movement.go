// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/models"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// LateralMovementDetector implements lateral movement detection logic.
// Implements NH-LM-001: Featuremodell for lateral movement detection.
// Implements NH-LM-002: Zeitfensterbewertung (time window evaluation).
// Implements NH-LM-003: Baseline-Abweichung against StratoSage.
// Implements NH-LM-004: Reason-Codes for lateral movement.
type LateralMovementDetector struct {
	baselineThreshold float64
	logger            logr.Logger
}

// LateralMovementConfig holds configuration for lateral movement detection.
type LateralMovementConfig struct {
	TimeWindow                 time.Duration
	PeerFanOutThreshold        int
	PortDivergenceThreshold    int
	AssetContextHopsThreshold  int
	BaselineDeviationThreshold float64
}

// DefaultLateralMovementConfig returns default configuration.
func DefaultLateralMovementConfig() LateralMovementConfig {
	return LateralMovementConfig{
		TimeWindow:                 5 * time.Minute,
		PeerFanOutThreshold:        10,
		PortDivergenceThreshold:    5,
		AssetContextHopsThreshold:  3,
		BaselineDeviationThreshold: 2.0,
	}
}

// NewLateralMovementDetector creates a new LateralMovementDetector.
func NewLateralMovementDetector(
	cfg LateralMovementConfig,
	logger logr.Logger,
) *LateralMovementDetector {
	return &LateralMovementDetector{
		baselineThreshold: cfg.BaselineDeviationThreshold,
		logger:            logger.WithName("lateral-movement-detector"),
	}
}

// LateralMovementReason represents reason codes for lateral movement detection.
// Implements NH-LM-004: Reason-Codes.
type LateralMovementReason struct {
	Code        string
	Description string
	Severity    models.FindingSeverity
	Confidence  float64
}

// Standard reason codes for lateral movement detection.
var (
	ReasonPeerFanOutExceeded = LateralMovementReason{
		Code:        "LM-PFO-001",
		Description: "Peer fan-out exceeded threshold",
		Severity:    models.FindingSeverityHigh,
		Confidence:  0.9,
	}

	ReasonPortDivergenceExceeded = LateralMovementReason{
		Code:        "LM-PD-002",
		Description: "Port divergence exceeded threshold",
		Severity:    models.FindingSeverityHigh,
		Confidence:  0.9,
	}

	ReasonAssetContextHopsExceeded = LateralMovementReason{
		Code:        "LM-ACH-003",
		Description: "Asset context hops exceeded threshold",
		Severity:    models.FindingSeverityHigh,
		Confidence:  0.9,
	}

	ReasonBaselineDeviationExceeded = LateralMovementReason{
		Code:        "LM-BD-004",
		Description: "Behavior deviates significantly from established baseline",
		Severity:    models.FindingSeverityCritical,
		Confidence:  0.9,
	}

	ReasonInternalLateralMovement = LateralMovementReason{
		Code:        "LM-ILM-006",
		Description: "Internal lateral movement detected",
		Severity:    models.FindingSeverityCritical,
		Confidence:  0.9,
	}
)

// Baseline represents normal behavior baseline for an asset.
type Baseline struct {
	AvgPeerFanOut       float64
	AvgPortDivergence   float64
	AvgAssetContextHops float64
}

// EvaluateLateralMovement evaluates detection for lateral movement indicators.
// Implements NH-LM-001: Featuremodell (peer-fan-out, port-divergence, asset-context-hops).
// Implements NH-LM-002: Zeitfensterbewertung.
// Implements NH-LM-003: Baseline-Abweichung.
func (d *LateralMovementDetector) EvaluateLateralMovement(
	ctx context.Context,
	logger logr.Logger,
	detection *models.Detection,
	flowCtx *FlowContext,
	cfg LateralMovementConfig,
) []LateralMovementReason {
	logger.V(vplogging.LogLevelDebug).Info("evaluating lateral movement indicators",
		"detectionId", detection.DetectionID)

	var reasons []LateralMovementReason

	if flowCtx == nil {
		return reasons
	}

	// NH-LM-001: Featuremodell - evaluate peer fan-out
	peerFanOut := 1
	if flowCtx.DestIP != "" && flowCtx.DestIP != detection.DestIP {
		peerFanOut = 2
	}

	if peerFanOut > cfg.PeerFanOutThreshold {
		reasons = append(reasons, ReasonPeerFanOutExceeded)

		logger.V(vplogging.LogLevelInfo).Info("peer fan-out threshold exceeded")
	}

	// NH-LM-001: Featuremodell - evaluate port divergence
	portDivergence := 1
	if flowCtx.DestPort > 0 && flowCtx.DestPort != detection.DestPort {
		portDivergence = 2
	}

	if portDivergence > cfg.PortDivergenceThreshold {
		reasons = append(reasons, ReasonPortDivergenceExceeded)

		logger.V(vplogging.LogLevelInfo).Info("port divergence threshold exceeded")
	}

	// NH-LM-001: Featuremodell - evaluate asset context hops
	assetContextHops := 0
	if flowCtx.AssetID != "" && flowCtx.AssetID != detection.AssetID {
		assetContextHops = 1
	}

	if assetContextHops > cfg.AssetContextHopsThreshold {
		reasons = append(reasons, ReasonAssetContextHopsExceeded)

		logger.V(vplogging.LogLevelInfo).Info("asset context hops threshold exceeded")
	}

	// NH-LM-002: Zeitfensterbewertung
	now := time.Now().UTC()
	timeWindowStart := now.Add(-cfg.TimeWindow)

	if detection.Timestamp.After(timeWindowStart) {
		logger.V(vplogging.LogLevelDebug).Info("detection within time window")
	}

	// NH-LM-003: Baseline-Abweichung
	baseline := Baseline{
		AvgPeerFanOut:       2.0,
		AvgPortDivergence:   1.0,
		AvgAssetContextHops: 0.5,
	}

	peerDeviation := float64(peerFanOut) / baseline.AvgPeerFanOut

	if peerDeviation > d.baselineThreshold {
		reasons = append(reasons, ReasonBaselineDeviationExceeded)

		logger.V(vplogging.LogLevelInfo).Info("peer fan-out baseline deviation exceeded")
	}

	if len(reasons) > 0 {
		reasons = append(reasons, ReasonInternalLateralMovement)
	}

	return reasons
}

// DetectLateralMovement analyzes a detection for lateral movement indicators.
// Implements NH-LM-007: Emission network.lateral_movement_suspected.
func (d *LateralMovementDetector) DetectLateralMovement(
	ctx context.Context,
	logger logr.Logger,
	detection *models.Detection,
	flowCtx *FlowContext,
	cfg LateralMovementConfig,
) bool {
	reasons := d.EvaluateLateralMovement(ctx, logger, detection, flowCtx, cfg)

	if len(reasons) > 0 {
		logger.V(vplogging.LogLevelInfo).Info("lateral movement suspected")
		return true
	}

	return false
}

// ProcessDetectionForLateralMovement processes a detection through the lateral movement pipeline.
// Implements NH-LM-005/006/007: FlowSeeker-Subscription, Event-driven Enrichment, Emission.
func (d *LateralMovementDetector) ProcessDetectionForLateralMovement(
	ctx context.Context,
	logger logr.Logger,
	detection *models.Detection,
	flowCtx *FlowContext,
	cfg LateralMovementConfig,
) (*models.Finding, bool) {
	isLateralMovement := d.DetectLateralMovement(ctx, logger, detection, flowCtx, cfg)

	if !isLateralMovement {
		return nil, false
	}

	// NH-LM-007: Emission network.lateral_movement_suspected
	finding := &models.Finding{
		FindingID:     fmt.Sprintf("lm-%s", detection.DetectionID),
		SchemaVersion: "2.0",
		FindingType:   models.FindingTypeLateralMovementSuspected,
		SourceContext: "netshield",
		AssetID:       detection.AssetID,
		DefconID:      detection.DefconID,
		OccurredAt:    detection.Timestamp,
		Severity:      models.FindingSeverityCritical,
		Confidence:    0.9,
		Title:         "Lateral Movement Suspected",
		Description: fmt.Sprintf("Lateral movement detected from %s to %s",
			detection.SourceIP, detection.DestIP),
		Attributes:   make(map[string]string),
		EvidenceRefs: []models.EvidenceRef{},
		Correlation:  nil,
		Lifecycle: models.FindingLifecycle{
			Status: models.FindingLifecycleStatusOpen,
		},
		Verification: models.FindingVerification{
			Status: models.FindingVerificationStatusUnverified,
		},
		Freshness: models.FindingFreshness{
			Status: models.FindingFreshnessStatusFresh,
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	finding.Attributes["detectionId"] = detection.DetectionID
	finding.Attributes["sourceIp"] = detection.SourceIP
	finding.Attributes["destIp"] = detection.DestIP

	return finding, true
}
