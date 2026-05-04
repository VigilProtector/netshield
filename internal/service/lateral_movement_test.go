// Package service provides the business logic layer for NetShield.
package service

import (
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

	detector := NewLateralMovementDetector(cfg, logger)

	assert.NotNil(t, detector, "Detector should not be nil")
	assert.Equal(t, cfg.BaselineDeviationThreshold, detector.baselineThreshold, "baselineThreshold should match config")
}

func TestEvaluateLateralMovement_NoFlowContext(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	detector := NewLateralMovementDetector(cfg, logger)

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
	assert.Equal(t, models.FindingSeverityCritical, finding.Severity, "Severity should be critical")
	assert.Equal(t, float64(0.9), finding.Confidence, "Confidence should be 0.9")
	assert.Contains(t, finding.Attributes, "detectionId", "Should contain detectionId in attributes")
}

func TestProcessDetectionForLateralMovement_NoMovement(t *testing.T) {
	cfg := DefaultLateralMovementConfig()
	logger := zap.New(zap.UseDevMode(true))
	detector := NewLateralMovementDetector(cfg, logger)

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
