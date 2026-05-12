// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"fmt"
	"strings"
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
	baselineProvider  BaselineProvider
	recentDetections  RecentDetectionsLister
	baselineThreshold float64
	logger            logr.Logger
}

// RecentDetectionsLister returns recent detections matching a source IP,
// used by the lateral-movement detector to aggregate features over the
// configured time window (peer-fan-out = distinct destIPs,
// port-divergence = distinct destPorts, asset-context-hops = distinct
// destAssetIDs).
//
// Consumer-defined interface — the production binding is
// *store.DetectionStore; tests inject a fake.
//
// Returning a nil slice / nil error is interpreted as "no recent
// activity" and the detector falls back to the single-detection view.
type RecentDetectionsLister interface {
	ListBySource(
		ctx context.Context,
		sourceIP string,
		since time.Time,
		maxItems int,
	) ([]models.Detection, error)
}

// maxRecentDetectionsPerWindow caps the per-cycle aggregation work. A
// noisy source bursting 10k events in 5 minutes is still bounded; the
// feature counts saturate at this value, which is well above any
// realistic threshold.
const maxRecentDetectionsPerWindow = 1000

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
//
// recentDetections is the source for the time-window feature aggregation
// (NH-LM-001 + NH-LM-002). May be nil; in that case the detector logs a
// warning on first use and falls back to the single-detection view —
// which is only meaningful for unit tests, never production.
func NewLateralMovementDetector(
	cfg LateralMovementConfig,
	logger logr.Logger,
	baselineProvider BaselineProvider,
	recentDetections RecentDetectionsLister,
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
		recentDetections:  recentDetections,
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

	// NH-LM-002: Zeitfensterbewertung — anchor on the current detection's
	// timestamp so the window slides correctly even when detections arrive
	// out of order.
	windowEnd := detection.Timestamp
	if windowEnd.IsZero() {
		windowEnd = time.Now().UTC()
	}

	windowStart := windowEnd.Add(-cfg.TimeWindow)

	// NH-LM-001: Featuremodell — aggregate over all detections from the
	// same sourceIP within the time window. Single-detection comparison
	// against flowCtx (the pre-fix behaviour) reduced features to {0,1,2}
	// which can never cross the production thresholds; counting distinct
	// destIPs / destPorts / destAssetIDs over the window gives the real
	// cardinality the threshold semantics actually expect.
	peerFanOut, portDivergence, assetContextHops := d.computeFeatures(
		ctx, logger, detection, flowCtx, windowStart,
	)

	logger.V(vplogging.LogLevelDebug).Info(
		"lateral-movement features",
		"sourceIp", detection.SourceIP,
		"peerFanOut", peerFanOut,
		"portDivergence", portDivergence,
		"assetContextHops", assetContextHops,
		"windowStart", windowStart,
		"windowEnd", windowEnd,
	)

	if peerFanOut > cfg.PeerFanOutThreshold {
		reasons = append(reasons, ReasonPeerFanOutExceeded)

		logger.V(vplogging.LogLevelInfo).Info("peer fan-out threshold exceeded",
			"value", peerFanOut, "threshold", cfg.PeerFanOutThreshold)
	}

	if portDivergence > cfg.PortDivergenceThreshold {
		reasons = append(reasons, ReasonPortDivergenceExceeded)

		logger.V(vplogging.LogLevelInfo).Info("port divergence threshold exceeded",
			"value", portDivergence, "threshold", cfg.PortDivergenceThreshold)
	}

	if assetContextHops > cfg.AssetContextHopsThreshold {
		reasons = append(reasons, ReasonAssetContextHopsExceeded)

		logger.V(vplogging.LogLevelInfo).Info("asset context hops threshold exceeded",
			"value", assetContextHops, "threshold", cfg.AssetContextHopsThreshold)
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
// Implements NH-LM-004 (VP-2234): the reason codes that fired are surfaced on the
// emitted Finding (Attributes["reasonCodes"] + human-readable Description) and the
// Finding's severity/confidence are derived from the highest-severity reason rather
// than hard-coded — so downstream worklists can prioritise correctly and an analyst
// can answer "why did this fire?" without re-running the detector.
func (d *LateralMovementDetector) ProcessDetectionForLateralMovement(
	ctx context.Context,
	logger logr.Logger,
	detection *models.Detection,
	flowCtx *FlowContext,
	cfg LateralMovementConfig,
) (*models.Finding, bool) {
	reasons := d.EvaluateLateralMovement(ctx, logger, detection, flowCtx, cfg)
	if len(reasons) == 0 {
		return nil, false
	}

	logger.V(vplogging.LogLevelInfo).Info("lateral movement suspected",
		"reasonCount", len(reasons),
	)

	severity, confidence := aggregateReasonSeverity(reasons)
	codes := reasonCodes(reasons)

	finding := &models.Finding{
		FindingID:     fmt.Sprintf("lm-%s", detection.DetectionID),
		SchemaVersion: "2.0",
		FindingType:   models.FindingTypeLateralMovementSuspected,
		SourceContext: "netshield",
		AssetID:       detection.AssetID,
		DefconID:      detection.DefconID,
		OccurredAt:    detection.Timestamp,
		Severity:      severity,
		Confidence:    confidence,
		Title:         "Lateral Movement Suspected",
		Description: fmt.Sprintf("Lateral movement detected from %s to %s (reasons: %s)",
			detection.SourceIP, detection.DestIP, strings.Join(codes, ",")),
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
	finding.Attributes["reasonCodes"] = strings.Join(codes, ",")

	// NH-CC-003 / VP-2235: surface cross-BC enrichment conflicts on the
	// emitted Finding so downstream worklists can flag low-trust evidence
	// without re-running the resolver. Confidence is reduced multiplicatively.
	if flowCtx != nil && flowCtx.Enrichment != nil {
		enrichment := flowCtx.Enrichment
		if len(enrichment.Conflicts) > 0 {
			finding.Attributes["crossbc.conflicts"] = strings.Join(enrichment.ConflictCodes(), ",")
		}

		finding.Attributes["crossbc.confidence"] = fmt.Sprintf("%.2f", enrichment.Confidence)
		finding.Confidence *= enrichment.Confidence
	}

	return finding, true
}

// reasonCodes returns the unique, order-preserving Code list from reasons.
func reasonCodes(reasons []LateralMovementReason) []string {
	seen := make(map[string]struct{}, len(reasons))
	codes := make([]string, 0, len(reasons))

	for _, r := range reasons {
		if _, ok := seen[r.Code]; ok {
			continue
		}

		seen[r.Code] = struct{}{}
		codes = append(codes, r.Code)
	}

	return codes
}

// aggregateReasonSeverity picks the highest severity across reasons and the
// matching confidence. The severity ordering follows models.FindingSeverity:
// Critical > High > Medium > Low.
func aggregateReasonSeverity(reasons []LateralMovementReason) (models.FindingSeverity, float64) {
	rank := map[models.FindingSeverity]int{
		models.FindingSeverityLow:      1,
		models.FindingSeverityMedium:   2,
		models.FindingSeverityHigh:     3,
		models.FindingSeverityCritical: 4,
	}

	severity := models.FindingSeverityLow
	confidence := 0.0

	for _, r := range reasons {
		if rank[r.Severity] > rank[severity] {
			severity = r.Severity
			confidence = r.Confidence
		} else if rank[r.Severity] == rank[severity] && r.Confidence > confidence {
			confidence = r.Confidence
		}
	}

	return severity, confidence
}

// computeFeatures aggregates the three NH-LM-001 features across all
// detections from the same sourceIP within the time window. Each
// feature is the cardinality of a distinct value set:
//
//   - peerFanOut       = |distinct destIP|
//   - portDivergence   = |distinct destPort|
//   - assetContextHops = |distinct destAssetID|
//
// The current detection is always included so the feature counts
// reflect "what we know right now", not "what was in the DB before
// this detection".
//
// If no RecentDetectionsLister is configured (unit-test setup), only
// the current detection contributes — the feature counts are 1/1/1 or
// 1/1/0 depending on whether AssetID is set. This is loud and useless
// for production, which is why the production wiring in cmd/main.go
// must inject the real DetectionStore.
func (d *LateralMovementDetector) computeFeatures(
	ctx context.Context,
	logger logr.Logger,
	detection *models.Detection,
	flowCtx *FlowContext,
	windowStart time.Time,
) (peerFanOut, portDivergence, assetContextHops int) {
	destIPs := make(map[string]struct{}, 4)
	destPorts := make(map[int]struct{}, 4)
	destAssets := make(map[string]struct{}, 4)

	addCurrent := func(destIP string, destPort int, assetID string) {
		if destIP != "" {
			destIPs[destIP] = struct{}{}
		}

		if destPort > 0 {
			destPorts[destPort] = struct{}{}
		}

		if assetID != "" && assetID != detection.AssetID {
			destAssets[assetID] = struct{}{}
		}
	}

	addCurrent(detection.DestIP, detection.DestPort, detection.AssetID)

	if flowCtx != nil {
		addCurrent(flowCtx.DestIP, flowCtx.DestPort, flowCtx.AssetID)
	}

	if d.recentDetections != nil && detection.SourceIP != "" {
		recent, err := d.recentDetections.ListBySource(
			ctx,
			detection.SourceIP,
			windowStart,
			maxRecentDetectionsPerWindow,
		)
		if err != nil {
			logger.V(vplogging.LogLevelInfo).Error(err,
				"failed to list recent detections for lateral-movement features",
				"sourceIp", detection.SourceIP,
			)
		} else {
			for i := range recent {
				row := recent[i]

				if row.DetectionID == detection.DetectionID {
					continue
				}

				addCurrent(row.DestIP, row.DestPort, row.AssetID)
			}
		}
	} else if d.recentDetections == nil {
		logger.V(vplogging.LogLevelInfo).Info(
			"no RecentDetectionsLister configured; lateral-movement features fall back to single-detection view — production must wire the DetectionStore",
		)
	}

	return len(destIPs), len(destPorts), len(destAssets)
}
