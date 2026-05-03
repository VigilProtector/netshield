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
