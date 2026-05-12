// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"vigilprotector.io/netshield/internal/models"
)

func TestDefaultLateralMovementConfig(t *testing.T) {
	cfg := DefaultLateralMovementConfig()

	assert.Equal(t, 5*time.Minute, cfg.TimeWindow, "TimeWindow should be 5 minutes")
	assert.Equal(t, 10, cfg.PeerFanOutThreshold, "PeerFanOutThreshold should be 10")
	assert.Equal(t, 5, cfg.PortDivergenceThreshold, "PortDivergenceThreshold should be 5")
	assert.Equal(t, 3, cfg.AssetContextHopsThreshold, "AssetContextHopsThreshold should be 3")
	assert.Equal(t, 2.0, cfg.BaselineDeviationThreshold, "BaselineDeviationThreshold should be 2.0")
}

func TestNewLateralMovementDetector(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))

	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	assert.NotNil(t, detector, "Detector should not be nil")
	assert.Equal(t, cfg.BaselineDeviationThreshold, detector.baselineThreshold, "baselineThreshold should match config")
}

func TestEvaluateLateralMovement_NoFlowContext(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		SourcePort:  12345,
		DestPort:    80,
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Test with nil flow context
	reasons := detector.EvaluateLateralMovement(t.Context(), logger, detection, nil, cfg)

	assert.Empty(t, reasons, "Should return no reasons when flow context is nil")
}

func TestEvaluateLateralMovement_PeerFanOutExceeded(t *testing.T) {
	cfg := LateralMovementConfig{
		TimeWindow:               5 * time.Minute,
		PeerFanOutThreshold:      1, // Set low threshold for testing
		PortDivergenceThreshold:  10,
		AssetContextHopsThreshold: 10,
		BaselineDeviationThreshold: 2.0,
	}
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Create flow context with different dest IP to trigger peer fan-out
	flowCtx := &FlowContext{
		DestIP: "192.168.1.3", // Different from detection.DestIP
	}

	reasons := detector.EvaluateLateralMovement(t.Context(), logger, detection, flowCtx, cfg)

	assert.NotEmpty(t, reasons, "Should return reasons when peer fan-out exceeded")
	assert.Contains(t, reasons, ReasonPeerFanOutExceeded, "Should contain peer fan-out exceeded reason")
}

func TestEvaluateLateralMovement_PortDivergenceExceeded(t *testing.T) {
	cfg := LateralMovementConfig{
		TimeWindow:               5 * time.Minute,
		PeerFanOutThreshold:      10,
		PortDivergenceThreshold:  1, // Set low threshold for testing
		AssetContextHopsThreshold: 10,
		BaselineDeviationThreshold: 2.0,
	}
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		DestPort:    80,
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Create flow context with different dest port to trigger port divergence
	flowCtx := &FlowContext{
		DestIP:   "192.168.1.2",
		DestPort: 443, // Different from detection.DestPort
	}

	reasons := detector.EvaluateLateralMovement(t.Context(), logger, detection, flowCtx, cfg)

	assert.NotEmpty(t, reasons, "Should return reasons when port divergence exceeded")
	assert.Contains(t, reasons, ReasonPortDivergenceExceeded, "Should contain port divergence exceeded reason")
}

func TestEvaluateLateralMovement_AssetContextHopsExceeded(t *testing.T) {
	cfg := LateralMovementConfig{
		TimeWindow:               5 * time.Minute,
		PeerFanOutThreshold:      10,
		PortDivergenceThreshold:  10,
		AssetContextHopsThreshold: 0, // Set threshold to 0 to trigger with assetContextHops=1
		BaselineDeviationThreshold: 2.0,
	}
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Create flow context with different asset ID to trigger context hops
	flowCtx := &FlowContext{
		DestIP:   "192.168.1.2",
		AssetID: "asset-2", // Different from detection.AssetID
	}

	reasons := detector.EvaluateLateralMovement(t.Context(), logger, detection, flowCtx, cfg)

	assert.NotEmpty(t, reasons, "Should return reasons when asset context hops exceeded")
	assert.Contains(t, reasons, ReasonAssetContextHopsExceeded, "Should contain asset context hops exceeded reason")
}

func TestEvaluateLateralMovement_BaselineDeviationExceeded(t *testing.T) {
	cfg := LateralMovementConfig{
		TimeWindow:               5 * time.Minute,
		PeerFanOutThreshold:      1, // Set low threshold
		PortDivergenceThreshold:  10,
		AssetContextHopsThreshold: 10,
		BaselineDeviationThreshold: 0.5, // Set very low threshold for testing (peerDeviation = 2/2 = 1 > 0.5)
	}
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Create flow context with different dest IP to trigger peer fan-out
	// This will cause peerDeviation = 2/2 = 1 > 0.5 threshold
	flowCtx := &FlowContext{
		DestIP: "192.168.1.3", // Different from detection.DestIP
	}

	reasons := detector.EvaluateLateralMovement(t.Context(), logger, detection, flowCtx, cfg)

	assert.NotEmpty(t, reasons, "Should return reasons when baseline deviation exceeded")
	assert.Contains(t, reasons, ReasonBaselineDeviationExceeded, "Should contain baseline deviation exceeded reason")
}

func TestEvaluateLateralMovement_NoThresholdsExceeded(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		DestPort:    80,
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Create flow context with same values - no thresholds exceeded
	flowCtx := &FlowContext{
		DestIP:   "192.168.1.2",
		DestPort: 80,
		AssetID: "asset-1",
	}

	reasons := detector.EvaluateLateralMovement(t.Context(), logger, detection, flowCtx, cfg)

	assert.Empty(t, reasons, "Should return no reasons when no thresholds exceeded")
}

func TestDetectLateralMovement(t *testing.T) {
	cfg := LateralMovementConfig{
		TimeWindow:               5 * time.Minute,
		PeerFanOutThreshold:      1,
		PortDivergenceThreshold:  10,
		AssetContextHopsThreshold: 10,
		BaselineDeviationThreshold: 2.0,
	}
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Test with flow context that triggers detection
	flowCtx := &FlowContext{
		DestIP: "192.168.1.3", // Different from detection.DestIP
	}

	isLateralMovement := detector.DetectLateralMovement(t.Context(), logger, detection, flowCtx, cfg)

	assert.True(t, isLateralMovement, "Should detect lateral movement when thresholds exceeded")
}

func TestDetectLateralMovement_NoMovement(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		DestPort:    80,
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Test with flow context that doesn't trigger detection
	flowCtx := &FlowContext{
		DestIP:   "192.168.1.2",
		DestPort: 80,
		AssetID: "asset-1",
	}

	isLateralMovement := detector.DetectLateralMovement(t.Context(), logger, detection, flowCtx, cfg)

	assert.False(t, isLateralMovement, "Should not detect lateral movement when no thresholds exceeded")
}

func TestProcessDetectionForLateralMovement(t *testing.T) {
	cfg := LateralMovementConfig{
		TimeWindow:               5 * time.Minute,
		PeerFanOutThreshold:      1,
		PortDivergenceThreshold:  10,
		AssetContextHopsThreshold: 10,
		BaselineDeviationThreshold: 2.0,
	}
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Test with flow context that triggers detection
	flowCtx := &FlowContext{
		DestIP: "192.168.1.3", // Different from detection.DestIP
	}

	finding, isLateralMovement := detector.ProcessDetectionForLateralMovement(
		t.Context(), logger, detection, flowCtx, cfg,
	)

	assert.True(t, isLateralMovement, "Should detect lateral movement")
	assert.NotNil(t, finding, "Should return a finding when lateral movement detected")
	assert.Equal(t, models.FindingTypeLateralMovementSuspected, finding.FindingType, "Finding type should be lateral movement suspected")
	assert.Equal(t, models.FindingSeverityCritical, finding.Severity, "Severity should be critical (highest reason wins)")
	assert.Equal(t, float64(0.9), finding.Confidence, "Confidence should be 0.9")
	assert.Contains(t, finding.Attributes, "detectionId", "Should contain detectionId in attributes")

	// NH-LM-004 / VP-2234: reason codes that fired must surface on the Finding.
	assert.Contains(t, finding.Attributes, "reasonCodes", "Should expose reasonCodes attribute")
	assert.NotEmpty(t, finding.Attributes["reasonCodes"], "reasonCodes attribute must not be empty when finding is emitted")
	assert.Contains(t, finding.Attributes["reasonCodes"], ReasonInternalLateralMovement.Code,
		"reasonCodes should contain the umbrella ILM-006 code when reasons fired")
	assert.True(t, strings.Contains(finding.Description, ReasonInternalLateralMovement.Code),
		"Description should reference the reason code")
}

// TestProcessDetectionForLateralMovement_ReasonCodesPropagated focusses on NH-LM-004
// (VP-2234): every reason that fires inside EvaluateLateralMovement must end up on the
// emitted Finding so the worklist consumer can render an explanation without re-running
// detection. Severity must be the highest severity across the reasons.
func TestProcessDetectionForLateralMovement_ReasonCodesPropagated(t *testing.T) {
	cfg := LateralMovementConfig{
		TimeWindow:                 5 * time.Minute,
		PeerFanOutThreshold:        1,
		PortDivergenceThreshold:    1,
		AssetContextHopsThreshold:  10,
		BaselineDeviationThreshold: 2.0,
	}
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-multi",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		DestPort:    443,
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}
	flowCtx := &FlowContext{
		DestIP:   "192.168.1.99",
		DestPort: 8080,
	}

	finding, isLateralMovement := detector.ProcessDetectionForLateralMovement(
		t.Context(), logger, detection, flowCtx, cfg,
	)

	assert.True(t, isLateralMovement)
	assert.NotNil(t, finding)

	codes := finding.Attributes["reasonCodes"]
	assert.Contains(t, codes, ReasonPeerFanOutExceeded.Code, "PFO-001 must be in reasonCodes")
	assert.Contains(t, codes, ReasonPortDivergenceExceeded.Code, "PD-002 must be in reasonCodes")
	assert.Contains(t, codes, ReasonInternalLateralMovement.Code, "ILM-006 umbrella must be in reasonCodes")
	assert.Equal(t, models.FindingSeverityCritical, finding.Severity,
		"highest reason severity (ILM-006 critical) must dominate")
}

func TestProcessDetectionForLateralMovement_NoMovement(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger, nil, nil)

	detection := &models.Detection{
		DetectionID: "test-detection-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		DestPort:    80,
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
	}

	// Test with flow context that doesn't trigger detection
	flowCtx := &FlowContext{
		DestIP:   "192.168.1.2",
		DestPort: 80,
		AssetID: "asset-1",
	}

	finding, isLateralMovement := detector.ProcessDetectionForLateralMovement(
		t.Context(), logger, detection, flowCtx, cfg,
	)

	assert.False(t, isLateralMovement, "Should not detect lateral movement")
	assert.Nil(t, finding, "Should return nil finding when no lateral movement detected")
}


// fakeRecentDetectionsLister returns a fixed slice of detections; used
// to exercise the new window-aggregated NH-LM-001 features against
// realistic flow histories.
type fakeRecentDetectionsLister struct {
	rows []models.Detection
}

func (f *fakeRecentDetectionsLister) ListBySource(
	_ context.Context,
	_ string,
	_ time.Time,
	_ int,
) ([]models.Detection, error) {
	return f.rows, nil
}

// TestEvaluateLateralMovement_DefaultThresholds_TriggerOnWindowAggregation
// pins the NH-LM-004 fix: with the production-default thresholds
// (10/5/3) the feature reasons fire exactly when the cardinality of
// distinct destIPs / destPorts / destAssetIDs from the same sourceIP
// over the time window exceeds them. The pre-fix binary feature
// computation made this impossible.
func TestEvaluateLateralMovement_DefaultThresholds_TriggerOnWindowAggregation(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))

	now := time.Now().UTC()
	sourceIP := "10.0.0.5"

	// 12 distinct destIPs / 7 distinct destPorts / 4 distinct destAssets.
	// All values cross the default thresholds (10 / 5 / 3) so all three
	// feature reasons must fire.
	rows := make([]models.Detection, 0, 12)
	for i := 0; i < 12; i++ {
		rows = append(rows, models.Detection{
			DetectionID: "older-" + string(rune('a'+i)),
			Timestamp:   now.Add(-time.Duration(i+1) * time.Second),
			SourceIP:    sourceIP,
			DestIP:      "10.1.0." + string(rune('0'+i%10)) + string(rune('0'+i/10)),
			DestPort:    1000 + i%7,
			AssetID:     "asset-" + string(rune('a'+i%4)),
		})
	}

	lister := &fakeRecentDetectionsLister{rows: rows}
	detector := NewLateralMovementDetector(cfg, logger, nil, lister)

	current := &models.Detection{
		DetectionID: "current-1",
		Timestamp:   now,
		SourceIP:    sourceIP,
		DestIP:      "10.1.0.99",
		DestPort:    1099,
		AssetID:     "asset-base",
	}

	reasons := detector.EvaluateLateralMovement(
		t.Context(), logger, current, &FlowContext{}, cfg,
	)

	codes := make(map[string]struct{}, len(reasons))
	for _, r := range reasons {
		codes[r.Code] = struct{}{}
	}

	assert.Contains(t, codes, ReasonPeerFanOutExceeded.Code,
		"window-aggregated peer fan-out must trigger against default threshold")
	assert.Contains(t, codes, ReasonPortDivergenceExceeded.Code,
		"window-aggregated port divergence must trigger against default threshold")
	assert.Contains(t, codes, ReasonAssetContextHopsExceeded.Code,
		"window-aggregated asset context hops must trigger against default threshold")
}

// TestEvaluateLateralMovement_DefaultThresholds_QuietBaseline locks down
// the inverse: a single benign flow against the same destination does
// NOT trip any feature reason under default config. Without the
// aggregation fix this would silently never fire either, so the test
// is meaningful only paired with the trigger test above.
func TestEvaluateLateralMovement_DefaultThresholds_QuietBaseline(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))

	lister := &fakeRecentDetectionsLister{rows: nil} // no history
	detector := NewLateralMovementDetector(cfg, logger, nil, lister)

	current := &models.Detection{
		DetectionID: "current-1",
		Timestamp:   time.Now().UTC(),
		SourceIP:    "10.0.0.5",
		DestIP:      "10.1.0.1",
		DestPort:    443,
		AssetID:     "asset-1",
	}

	reasons := detector.EvaluateLateralMovement(
		t.Context(), logger, current, &FlowContext{}, cfg,
	)

	for _, r := range reasons {
		assert.NotEqual(t, ReasonPeerFanOutExceeded.Code, r.Code, "single flow must not trip peer fan-out")
		assert.NotEqual(t, ReasonPortDivergenceExceeded.Code, r.Code, "single flow must not trip port divergence")
		assert.NotEqual(t, ReasonAssetContextHopsExceeded.Code, r.Code, "single flow must not trip asset context hops")
	}
}
