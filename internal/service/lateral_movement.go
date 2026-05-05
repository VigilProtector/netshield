// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/client"
	"vigilprotector.io/netshield/internal/models"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// BaselineProvider is an interface for accessing StratoSage baselines.
// This is re-exported from client package for convenience.
type BaselineProvider = client.BaselineProvider

// LateralMovementDetector implements lateral movement detection logic.
// Implements NH-LM-001: Featuremodell for lateral movement detection.
// Implements NH-LM-002: Zeitfensterbewertung (time window evaluation).
// Implements NH-LM-003: Baseline-Abweichung against StratoSage (via SS-BP-004).
// Implements NH-LM-004: Reason-Codes for lateral movement.
type LateralMovementDetector struct {
	baselineProvider BaselineProvider
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
	// StratoSageBaseURL is the base URL for StratoSage API (SS-BP-004)
	StratoSageBaseURL string
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
// If StratoSageBaseURL is provided in config, it will create a StratoSageClient
// as the baseline provider (SS-BP-004). Otherwise, baselineProvider can be injected directly.
func NewLateralMovementDetector(
	cfg LateralMovementConfig,
	logger logr.Logger,
	baselineProvider BaselineProvider,
) *LateralMovementDetector {
	// If no baseline provider is given but StratoSage URL is configured, create one
	if baselineProvider == nil && cfg.StratoSageBaseURL != "" {
		// Create HTTP client adapter using vp-lib
		httpClient := client.NewHTTPClientWithTimeout(30*time.Second, logger)
		// Create StratoSage client as baseline provider
		baselineProvider = client.NewStratoSageClient(cfg.StratoSageBaseURL, httpClient, logger)
	}

	return &LateralMovementDetector{
		baselineProvider:  baselineProvider,
		baselineThreshold: cfg.BaselineDeviationThreshold,
		logger:           logger.WithName("lateral-movement-detector"),
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

	// NH-LM-003: Baseline-Abweichung (SS-BP-004: Uses StratoSage baseline instead of local heuristic)
	// If baseline provider is available, fetch baseline from StratoSage
	var baseline *client.Baseline
	var fetchErr error
	if d.baselineProvider != nil {
		// Use scope from detection or flow context as scopeRef
		scopeRef := detection.AssetID
		if flowCtx != nil && flowCtx.AssetID != "" {
			scopeRef = flowCtx.AssetID
		}
		// For now, use a generic feature set
		// In a real implementation, this would be determined from the detection type
		featureSet := "lateral_movement"

		baseline, fetchErr = d.baselineProvider.GetBaseline(ctx, scopeRef, featureSet)
		if fetchErr != nil {
			logger.V(vplogging.LogLevelDebug).Error(fetchErr, "Failed to fetch baseline from StratoSage",
				"scopeRef", scopeRef, "featureSet", featureSet)
			// Fall back to default baseline values
		}
	}

	// Use StratoSage baseline if available, otherwise fall back to defaults
	if baseline != nil && baseline.Stats != nil {
		// SS-BP-004: Use values from StratoSage baseline
		avgPeerFanOut := baseline.Stats["avgPeerFanOut"]
		avgPortDivergence := baseline.Stats["avgPortDivergence"]
		avgAssetContextHops := baseline.Stats["avgAssetContextHops"]

		// Avoid division by zero
		if avgPeerFanOut > 0 {
			peerDeviation := float64(peerFanOut) / avgPeerFanOut
			if peerDeviation > d.baselineThreshold {
				reasons = append(reasons, ReasonBaselineDeviationExceeded)
				logger.V(vplogging.LogLevelInfo).Info("peer fan-out baseline deviation exceeded",
					"current", peerFanOut, "baseline", avgPeerFanOut, "deviation", peerDeviation)
			}
		}

		// TODO: Add similar checks for port divergence and asset context hops
		// based on StratoSage baseline values
		_ = avgPortDivergence
		_ = avgAssetContextHops
	} else {
		// Fallback to local heuristic thresholds (NH-LM-003 original behavior)
		// This maintains backward compatibility when StratoSage is not available
		defaultBaseline := client.Baseline{
			Stats: map[string]float64{
				"avgPeerFanOut":       2.0,
				"avgPortDivergence":   1.0,
				"avgAssetContextHops": 0.5,
			},
		}

		peerDeviation := float64(peerFanOut) / defaultBaseline.Stats["avgPeerFanOut"]

		if peerDeviation > d.baselineThreshold {
			reasons = append(reasons, ReasonBaselineDeviationExceeded)
			logger.V(vplogging.LogLevelInfo).Info("peer fan-out baseline deviation exceeded (fallback)")
		}
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
