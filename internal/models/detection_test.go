// Package models provides domain models for NetShield.
package models

import (
	"testing"
	"time"
)

// TestDetectionEventType tests the DetectionEventType constants.
func TestDetectionEventType(t *testing.T) {
	tests := []struct {
		name     string
		event    DetectionEventType
		expected string
	}{
		{"alert", DetectionEventTypeAlert, "alert"},
		{"anomaly", DetectionEventTypeAnomaly, "anomaly"},
		{"lateral_movement", DetectionEventTypeLateralMovement, "lateral_movement"},
		{"policy_violation", DetectionEventTypePolicyViolation, "policy_violation"},
		{"flow", DetectionEventTypeFlow, "flow"},
		{"dns", DetectionEventTypeDNS, "dns"},
		{"http", DetectionEventTypeHTTP, "http"},
		{"tls", DetectionEventTypeTLS, "tls"},
		{"file", DetectionEventTypeFile, "file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.event) != tt.expected {
				t.Errorf("DetectionEventType = %v, want %v", string(tt.event), tt.expected)
			}
		})
	}
}

// TestRuleSeverity tests the RuleSeverity constants.
func TestRuleSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity RuleSeverity
		expected string
	}{
		{"critical", RuleSeverityCritical, "critical"},
		{"high", RuleSeverityHigh, "high"},
		{"medium", RuleSeverityMedium, "medium"},
		{"low", RuleSeverityLow, "low"},
		{"informational", RuleSeverityInformational, "informational"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.severity) != tt.expected {
				t.Errorf("RuleSeverity = %v, want %v", string(tt.severity), tt.expected)
			}
		})
	}
}

// TestConfidenceLevel tests the ConfidenceLevel constants.
func TestConfidenceLevel(t *testing.T) {
	tests := []struct {
		name       string
		confidence ConfidenceLevel
		expected   string
	}{
		{"high", ConfidenceHigh, "high"},
		{"medium", ConfidenceMedium, "medium"},
		{"low", ConfidenceLow, "low"},
		{"unknown", ConfidenceUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.confidence) != tt.expected {
				t.Errorf("ConfidenceLevel = %v, want %v", string(tt.confidence), tt.expected)
			}
		})
	}
}

// TestDetectionToAPI tests the ToAPI conversion for Detection.
func TestDetectionToAPI(t *testing.T) {
	now := time.Now().UTC()
	detection := &Detection{
		DetectionID: "det-001",
		SensorID:    "sensor-001",
		PicketID:    "picket-001",
		RuleSetID:   "ruleset-001",
		RuleID:      "rule-001",
		EventType:   DetectionEventTypeAlert,
		Timestamp:   now,
		Signature:   "ET OPEN Rule 1",
		Category:    "Malware",
		Severity:    RuleSeverityHigh,
		Confidence:  ConfidenceHigh,
		SourceIP:    "192.168.1.1",
		DestIP:      "10.0.0.1",
		SourcePort:  12345,
		DestPort:    80,
		Proto:       "TCP",
		AssetID:     "asset-001",
		DefconID:    "defcon-001",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	api := detection.ToAPI()

	if api.DetectionID != detection.DetectionID {
		t.Errorf("ToAPI() DetectionID = %v, want %v", api.DetectionID, detection.DetectionID)
	}
	if api.SensorID != detection.SensorID {
		t.Errorf("ToAPI() SensorID = %v, want %v", api.SensorID, detection.SensorID)
	}
	if api.EventType != string(detection.EventType) {
		t.Errorf("ToAPI() EventType = %v, want %v", api.EventType, string(detection.EventType))
	}
	if api.Severity != string(detection.Severity) {
		t.Errorf("ToAPI() Severity = %v, want %v", api.Severity, string(detection.Severity))
	}
	if api.Confidence != string(detection.Confidence) {
		t.Errorf("ToAPI() Confidence = %v, want %v", api.Confidence, string(detection.Confidence))
	}
	if api.SourceIP != detection.SourceIP {
		t.Errorf("ToAPI() SourceIP = %v, want %v", api.SourceIP, detection.SourceIP)
	}
}

// TestDetectionFromAPI tests the FromAPI conversion for Detection.
func TestDetectionFromAPI(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		api := &DetectionAPI{
			DetectionID: "det-001",
			SensorID:    "sensor-001",
			PicketID:    "picket-001",
			RuleSetID:   "ruleset-001",
			RuleID:      "rule-001",
			EventType:   "alert",
			Timestamp:   now.Format(time.RFC3339),
			Signature:   "ET OPEN Rule 1",
			Category:    "Malware",
			Severity:    "high",
			Confidence:  "high",
			SourceIP:    "192.168.1.1",
			DestIP:      "10.0.0.1",
			SourcePort:  12345,
			DestPort:    80,
			Proto:       "TCP",
			AssetID:     "asset-001",
			DefconID:    "defcon-001",
			CreatedAt:   now.Format(time.RFC3339),
			UpdatedAt:   now.Format(time.RFC3339),
		}

		detection, err := api.FromAPI()
		if err != nil {
			t.Fatalf("FromAPI() error = %v", err)
		}

		if detection.DetectionID != api.DetectionID {
			t.Errorf("FromAPI() DetectionID = %v, want %v", detection.DetectionID, api.DetectionID)
		}
		if detection.SensorID != api.SensorID {
			t.Errorf("FromAPI() SensorID = %v, want %v", detection.SensorID, api.SensorID)
		}
		if detection.EventType != DetectionEventTypeAlert {
			t.Errorf("FromAPI() EventType = %v, want %v", detection.EventType, DetectionEventTypeAlert)
		}
		if detection.Severity != RuleSeverityHigh {
			t.Errorf("FromAPI() Severity = %v, want %v", detection.Severity, RuleSeverityHigh)
		}
		if detection.Confidence != ConfidenceHigh {
			t.Errorf("FromAPI() Confidence = %v, want %v", detection.Confidence, ConfidenceHigh)
		}
	})

	t.Run("invalid timestamp", func(t *testing.T) {
		t.Parallel()

		api := &DetectionAPI{
			Timestamp: "invalid-time",
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid timestamp, got nil")
		}
	})

	t.Run("invalid createdAt", func(t *testing.T) {
		t.Parallel()

		api := &DetectionAPI{
			Timestamp:  time.Now().Format(time.RFC3339),
			CreatedAt: "invalid-time",
			UpdatedAt: time.Now().Format(time.RFC3339),
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid createdAt, got nil")
		}
	})

	t.Run("invalid updatedAt", func(t *testing.T) {
		t.Parallel()

		api := &DetectionAPI{
			Timestamp:  time.Now().Format(time.RFC3339),
			CreatedAt:  time.Now().Format(time.RFC3339),
			UpdatedAt: "invalid-time",
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid updatedAt, got nil")
		}
	})
}

// TestIsDetectionEvent tests the IsDetectionEvent method.
func TestIsDetectionEvent(t *testing.T) {
	tests := []struct {
		name  string
		event DetectionEventType
		want  bool
	}{
		{"alert is detection", DetectionEventTypeAlert, true},
		{"anomaly is detection", DetectionEventTypeAnomaly, true},
		{"lateral_movement is detection", DetectionEventTypeLateralMovement, true},
		{"flow is not detection", DetectionEventTypeFlow, false},
		{"dns is not detection", DetectionEventTypeDNS, false},
		{"http is not detection", DetectionEventTypeHTTP, false},
		{"tls is not detection", DetectionEventTypeTLS, false},
		{"file is not detection", DetectionEventTypeFile, false},
		{"policy_violation is detection", DetectionEventTypePolicyViolation, true},
		{"empty is not detection", DetectionEventType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.IsDetectionEvent(); got != tt.want {
				t.Errorf("IsDetectionEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCreateFindingFromDetection tests the CreateFindingFromDetection function.
func TestCreateFindingFromDetection(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	detection := &Detection{
		DetectionID: "det-001",
		SensorID:    "sensor-001",
		PicketID:    "picket-001",
		RuleSetID:   "ruleset-001",
		RuleVersion: "v1.0",
		RuleID:      "rule-001",
		EventType:   DetectionEventTypeAlert,
		Timestamp:   now,
		Signature:   "ET OPEN Rule 1",
		Category:    "Malware",
		Severity:    RuleSeverityHigh,
		Confidence:  ConfidenceHigh,
		SourceIP:    "192.168.1.1",
		DestIP:      "10.0.0.1",
		SourcePort:  12345,
		DestPort:    80,
		Proto:       "TCP",
		Action:      "blocked",
		RawEvent:    "raw event data",
		EvidenceRefs: []string{"eve-001", "eve-002"},
	}

	finding := CreateFindingFromDetection(detection, "defcon-001", "asset-001")

	if finding == nil {
		t.Fatal("CreateFindingFromDetection returned nil")
	}

	// Test basic fields
	if finding.FindingID != "fnd_det-001" {
		t.Errorf("FindingID = %v, want %v", finding.FindingID, "fnd_det-001")
	}
	if finding.SchemaVersion != FindingContractVersion {
		t.Errorf("SchemaVersion = %v, want %v", finding.SchemaVersion, FindingContractVersion)
	}
	if finding.SourceContext != "netshield" {
		t.Errorf("SourceContext = %v, want %v", finding.SourceContext, "netshield")
	}
	if finding.AssetID != "asset-001" {
		t.Errorf("AssetID = %v, want %v", finding.AssetID, "asset-001")
	}
	if finding.DefconID != "defcon-001" {
		t.Errorf("DefconID = %v, want %v", finding.DefconID, "defcon-001")
	}
	if !finding.OccurredAt.Equal(now) {
		t.Errorf("OccurredAt = %v, want %v", finding.OccurredAt, now)
	}

	// Test mapped severity
	if finding.Severity != FindingSeverityHigh {
		t.Errorf("Severity = %v, want %v", finding.Severity, FindingSeverityHigh)
	}

	// Test mapped confidence
	if finding.Confidence != 0.9 {
		t.Errorf("Confidence = %v, want %v", finding.Confidence, 0.9)
	}

	// Test mapped finding type
	if finding.FindingType != FindingTypeKnownAttackPatternDetected {
		t.Errorf("FindingType = %v, want %v", finding.FindingType, FindingTypeKnownAttackPatternDetected)
	}

	// Test evidence refs
	if len(finding.EvidenceRefs) != 3 {
		t.Errorf("EvidenceRefs length = %v, want %v", len(finding.EvidenceRefs), 3)
	}

	// Test attributes
	if finding.Attributes["ruleId"] != "rule-001" {
		t.Errorf("Attributes[ruleId] = %v, want %v", finding.Attributes["ruleId"], "rule-001")
	}
	if finding.Attributes["sourceIp"] != "192.168.1.1" {
		t.Errorf("Attributes[sourceIp] = %v, want %v", finding.Attributes["sourceIp"], "192.168.1.1")
	}

	// Test title
	if finding.Title != "NetShield Detection: ET OPEN Rule 1" {
		t.Errorf("Title = %v, want %v", finding.Title, "NetShield Detection: ET OPEN Rule 1")
	}

	// Test description
	if finding.Description != "Detection from NetShield: ET OPEN Rule 1 | Raw: raw event data" {
		t.Errorf("Description = %v, want %v", finding.Description, "Detection from NetShield: ET OPEN Rule 1 | Raw: raw event data")
	}

	// Test lifecycle status
	if finding.Lifecycle.Status != FindingLifecycleStatusOpen {
		t.Errorf("Lifecycle.Status = %v, want %v", finding.Lifecycle.Status, FindingLifecycleStatusOpen)
	}
}

// TestMapSeverity tests the mapSeverity function.
func TestMapSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity RuleSeverity
		want     FindingSeverity
	}{
		{"critical", RuleSeverityCritical, FindingSeverityCritical},
		{"high", RuleSeverityHigh, FindingSeverityHigh},
		{"medium", RuleSeverityMedium, FindingSeverityMedium},
		{"low", RuleSeverityLow, FindingSeverityLow},
		{"informational", RuleSeverityInformational, FindingSeverityInfo},
		{"unknown", RuleSeverity("unknown"), FindingSeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSeverity(tt.severity)
			if got != tt.want {
				t.Errorf("mapSeverity(%v) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

// TestMapConfidenceToFloat tests the mapConfidenceToFloat function.
func TestMapConfidenceToFloat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		confidence ConfidenceLevel
		want       float64
	}{
		{"high", ConfidenceHigh, 0.9},
		{"medium", ConfidenceMedium, 0.6},
		{"low", ConfidenceLow, 0.3},
		{"unknown", ConfidenceUnknown, 0.0},
		{"empty", ConfidenceLevel(""), 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapConfidenceToFloat(tt.confidence)
			if got != tt.want {
				t.Errorf("mapConfidenceToFloat(%v) = %v, want %v", tt.confidence, got, tt.want)
			}
		})
	}
}

// TestMapDetectionTypeToFindingType tests the mapDetectionTypeToFindingType function.
func TestMapDetectionTypeToFindingType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event DetectionEventType
		want  FindingType
	}{
		{"alert", DetectionEventTypeAlert, FindingTypeKnownAttackPatternDetected},
		{"anomaly", DetectionEventTypeAnomaly, FindingTypeKnownAttackPatternDetected},
		{"lateral_movement", DetectionEventTypeLateralMovement, FindingTypeLateralMovementSuspected},
		{"policy_violation", DetectionEventTypePolicyViolation, FindingTypeNetworkPolicyViolationDetected},
		{"flow (non-detection)", DetectionEventTypeFlow, FindingTypeKnownAttackPatternDetected},
		{"dns (non-detection)", DetectionEventTypeDNS, FindingTypeKnownAttackPatternDetected},
		{"empty", DetectionEventType(""), FindingTypeKnownAttackPatternDetected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapDetectionTypeToFindingType(tt.event)
			if got != tt.want {
				t.Errorf("mapDetectionTypeToFindingType(%v) = %v, want %v", tt.event, got, tt.want)
			}
		})
	}
}
