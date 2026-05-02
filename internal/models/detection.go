// Package models contains the data models for NetShield service.
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Detection represents a detected event from Suricata.
// Part of the Detection-Pipeline (NH-CC-001, NH-LM-001).
type Detection struct {
	ID            bson.ObjectID     `bson:"_id,omitempty" json:"-"`
	DetectionID  string            `bson:"detectionId" json:"detectionId"`
	SensorID     string            `bson:"sensorId" json:"sensorId"`
	PicketID     string            `bson:"picketId" json:"picketId"`
	RuleSetID    string            `bson:"ruleSetId" json:"ruleSetId"`
	RuleVersion   string            `bson:"ruleVersion" json:"ruleVersion"`
	RuleID       string            `bson:"ruleId" json:"ruleId"`
	EventType    DetectionEventType `bson:"eventType" json:"eventType"`
	Timestamp    time.Time         `bson:"timestamp" json:"timestamp"`
	SourceIP     string            `bson:"sourceIp,omitempty" json:"sourceIp,omitempty"`
	DestIP       string            `bson:"destIp,omitempty" json:"destIp,omitempty"`
	SourcePort   int               `bson:"sourcePort,omitempty" json:"sourcePort,omitempty"`
	DestPort     int               `bson:"destPort,omitempty" json:"destPort,omitempty"`
	Proto        string            `bson:"proto,omitempty" json:"proto,omitempty"`
	Action       string            `bson:"action,omitempty" json:"action,omitempty"`
	Signature    string            `bson:"signature" json:"signature"`
	Category     string            `bson:"category" json:"category"`
	Severity     RuleSeverity      `bson:"severity" json:"severity"`
	Confidence   ConfidenceLevel   `bson:"confidence" json:"confidence"`
	Message      string            `bson:"message" json:"message"`
	RawEvent     string            `bson:"rawEvent,omitempty" json:"rawEvent,omitempty"`
	EvidenceRefs []string          `bson:"evidenceRefs,omitempty" json:"evidenceRefs,omitempty"`
	CreatedAt    time.Time         `bson:"createdAt" json:"createdAt"`
	UpdatedAt    time.Time         `bson:"updatedAt" json:"updatedAt"`
}

// DetectionAPI represents a detection for API responses.
type DetectionAPI struct {
	DetectionID  string    `json:"detectionId"`
	SensorID     string    `json:"sensorId"`
	PicketID     string    `json:"picketId"`
	RuleSetID    string    `json:"ruleSetId"`
	RuleVersion   string    `json:"ruleVersion"`
	RuleID       string    `json:"ruleId"`
	EventType    string    `json:"eventType"`
	Timestamp    string    `json:"timestamp"`
	SourceIP     string    `json:"sourceIp,omitempty"`
	DestIP       string    `json:"destIp,omitempty"`
	SourcePort   int       `json:"sourcePort,omitempty"`
	DestPort     int       `json:"destPort,omitempty"`
	Proto        string    `json:"proto,omitempty"`
	Action       string    `json:"action,omitempty"`
	Signature    string    `json:"signature"`
	Category     string    `json:"category"`
	Severity     string    `json:"severity"`
	Confidence   string    `json:"confidence"`
	Message      string    `json:"message"`
	RawEvent     string    `json:"rawEvent,omitempty"`
	EvidenceRefs []string  `json:"evidenceRefs,omitempty"`
	CreatedAt    string    `json:"createdAt"`
	UpdatedAt    string    `json:"updatedAt"`
}

// DetectionListResponse wraps a list of detections for API responses.
type DetectionListResponse struct {
	Items      []*Detection `json:"items"`
	TotalCount int          `json:"totalCount"`
	Limit      int          `json:"limit"`
	Offset     int          `json:"offset"`
}

// DetectionEventType represents the type of detection event.
type DetectionEventType string

const (
	// DetectionEventTypeAlert indicates a Suricata alert event.
	// NH-SG-009: Only alert and anomaly go to NetShield.
	DetectionEventTypeAlert DetectionEventType = "alert"
	// DetectionEventTypeAnomaly indicates a Suricata anomaly event.
	DetectionEventTypeAnomaly DetectionEventType = "anomaly"
	// DetectionEventTypeLateralMovement indicates a lateral movement detection.
	DetectionEventTypeLateralMovement DetectionEventType = "lateral_movement"
	// DetectionEventTypePolicyViolation indicates a policy violation.
	DetectionEventTypePolicyViolation DetectionEventType = "policy_violation"
	// DetectionEventTypeFlow indicates a flow event.
	DetectionEventTypeFlow DetectionEventType = "flow"
	// DetectionEventTypeDns indicates a DNS event.
	DetectionEventTypeDns DetectionEventType = "dns"
	// DetectionEventTypeHttp indicates an HTTP event.
	DetectionEventTypeHttp DetectionEventType = "http"
	// DetectionEventTypeTls indicates a TLS event.
	DetectionEventTypeTls DetectionEventType = "tls"
	// DetectionEventTypeFile indicates a file event.
	DetectionEventTypeFile DetectionEventType = "file"
)

// ConfidenceLevel represents the confidence level of a detection.
type ConfidenceLevel string

const (
	// ConfidenceHigh indicates high confidence.
	ConfidenceHigh ConfidenceLevel = "high"
	// ConfidenceMedium indicates medium confidence.
	ConfidenceMedium ConfidenceLevel = "medium"
	// ConfidenceLow indicates low confidence.
	ConfidenceLow ConfidenceLevel = "low"
	// ConfidenceUnknown indicates unknown confidence.
	ConfidenceUnknown ConfidenceLevel = "unknown"
)

// IsDetectionEvent returns true if the event type should be routed to NetShield.
// Implements NH-SG-009: Phase-1-Scope: nur alert/anomaly an NetShield.
func (e DetectionEventType) IsDetectionEvent() bool {
	switch e {
	case DetectionEventTypeAlert, DetectionEventTypeAnomaly, DetectionEventTypeLateralMovement, DetectionEventTypePolicyViolation:
		return true
	default:
		return false
	}
}

// DetectionFilter defines filter options for listing detections.
type DetectionFilter struct {
	SensorID   string `json:"sensorId,omitempty"`
	PicketID   string `json:"picketId,omitempty"`
	RuleSetID  string `json:"ruleSetId,omitempty"`
	RuleID     string `json:"ruleId,omitempty"`
	EventType  string `json:"eventType,omitempty"`
	Severity   string `json:"severity,omitempty"`
	StartTime  string `json:"startTime,omitempty"`
	EndTime    string `json:"endTime,omitempty"`
}

// ListDetectionsOptions defines options for listing detections.
type ListDetectionsOptions struct {
	Filter  DetectionFilter `json:"filter,omitempty"`
	Limit   int             `json:"limit,omitempty"`
	Offset  int             `json:"offset,omitempty"`
	SortBy  string          `json:"sortBy,omitempty"`
	SortAsc bool            `json:"sortAsc,omitempty"`
}

// ToAPI converts a Detection to a DetectionAPI.
func (d *Detection) ToAPI() *DetectionAPI {
	return &DetectionAPI{
		DetectionID:  d.DetectionID,
		SensorID:     d.SensorID,
		PicketID:     d.PicketID,
		RuleSetID:    d.RuleSetID,
		RuleVersion:   d.RuleVersion,
		RuleID:       d.RuleID,
		EventType:    string(d.EventType),
		Timestamp:    d.Timestamp.Format(time.RFC3339),
		SourceIP:     d.SourceIP,
		DestIP:       d.DestIP,
		SourcePort:   d.SourcePort,
		DestPort:     d.DestPort,
		Proto:        d.Proto,
		Action:       d.Action,
		Signature:    d.Signature,
		Category:     d.Category,
		Severity:     string(d.Severity),
		Confidence:   string(d.Confidence),
		Message:      d.Message,
		RawEvent:     d.RawEvent,
		EvidenceRefs: d.EvidenceRefs,
		CreatedAt:    d.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    d.UpdatedAt.Format(time.RFC3339),
	}
}

// FromAPI converts a DetectionAPI to a Detection.
func (d *DetectionAPI) FromAPI() (*Detection, error) {
	timestamp, err := time.Parse(time.RFC3339, d.Timestamp)
	if err != nil {
		return nil, err
	}
	createdAt, err := time.Parse(time.RFC3339, d.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := time.Parse(time.RFC3339, d.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &Detection{
		DetectionID:  d.DetectionID,
		SensorID:     d.SensorID,
		PicketID:     d.PicketID,
		RuleSetID:    d.RuleSetID,
		RuleVersion:   d.RuleVersion,
		RuleID:       d.RuleID,
		EventType:    DetectionEventType(d.EventType),
		Timestamp:    timestamp,
		SourceIP:     d.SourceIP,
		DestIP:       d.DestIP,
		SourcePort:   d.SourcePort,
		DestPort:     d.DestPort,
		Proto:        d.Proto,
		Action:       d.Action,
		Signature:    d.Signature,
		Category:     d.Category,
		Severity:     RuleSeverity(d.Severity),
		Confidence:   ConfidenceLevel(d.Confidence),
		Message:      d.Message,
		RawEvent:     d.RawEvent,
		EvidenceRefs: d.EvidenceRefs,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}, nil
}

// CreateFindingFromDetection creates a Finding from a Detection.
// Implements NH-LM-007: Emission network.lateral_movement_suspected.
// Maps detection to Finding Contract v2.
func CreateFindingFromDetection(d *Detection, defconID, assetID string) *Finding {
	// Map detection severity to finding severity
	severity := mapSeverity(d.Severity)

	// Create evidence refs
	evidenceRefs := make([]EvidenceRef, len(d.EvidenceRefs))
	for i, ref := range d.EvidenceRefs {
		evidenceRefs[i] = EvidenceRef{
			Type: "suricata_event",
			Ref:  ref,
		}
	}

	// Add detection ID as evidence
	evidenceRefs = append(evidenceRefs, EvidenceRef{
		Type: "netshield_detection",
		Ref:  d.DetectionID,
	})

	// Map detection event type to finding type
	findingType := mapDetectionTypeToFindingType(d.EventType)

	// Create attributes
	attributes := map[string]string{
		"ruleId":       d.RuleID,
		"ruleVersion":  d.RuleVersion,
		"ruleSetId":    d.RuleSetID,
		"sensorId":     d.SensorID,
		"picketId":     d.PicketID,
		"eventType":    string(d.EventType),
		"confidence":   string(d.Confidence),
	}

	if d.SourceIP != "" {
		attributes["sourceIp"] = d.SourceIP
	}
	if d.DestIP != "" {
		attributes["destIp"] = d.DestIP
	}
	if d.Proto != "" {
		attributes["proto"] = d.Proto
	}
	if d.Action != "" {
		attributes["action"] = d.Action
	}
	if d.Signature != "" {
		attributes["signature"] = d.Signature
	}
	if d.Category != "" {
		attributes["category"] = d.Category
	}

	// Create description
	description := "Detection from NetShield: " + d.Signature
	if d.RawEvent != "" {
		description += " | Raw: " + d.RawEvent
	}

	return &Finding{
		FindingID:     "fnd_" + d.DetectionID, // Prefix with fnd_ for global uniqueness
		SchemaVersion: FindingContractVersion,
		FindingType:   findingType,
		SourceContext: "netshield",
		AssetID:       assetID,
		DefconID:      defconID,
		OccurredAt:    d.Timestamp,
		Severity:      severity,
		Confidence:    mapConfidenceToFloat(d.Confidence),
		Title:         "NetShield Detection: " + d.Signature,
		Description:   description,
		Attributes:    attributes,
		EvidenceRefs:  evidenceRefs,
		Lifecycle: FindingLifecycle{
			Status: FindingLifecycleStatusOpen,
		},
		Verification: FindingVerification{
			Status: FindingVerificationStatusUnverified,
		},
		Freshness: FindingFreshness{
			Status: FindingFreshnessStatusFresh,
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// mapSeverity maps RuleSeverity to FindingSeverity.
func mapSeverity(severity RuleSeverity) FindingSeverity {
	switch severity {
	case RuleSeverityCritical:
		return FindingSeverityCritical
	case RuleSeverityHigh:
		return FindingSeverityHigh
	case RuleSeverityMedium:
		return FindingSeverityMedium
	case RuleSeverityLow:
		return FindingSeverityLow
	default:
		return FindingSeverityInfo
	}
}

// mapConfidenceToFloat maps ConfidenceLevel to float64.
func mapConfidenceToFloat(confidence ConfidenceLevel) float64 {
	switch confidence {
	case ConfidenceHigh:
		return 0.9
	case ConfidenceMedium:
		return 0.6
	case ConfidenceLow:
		return 0.3
	default:
		return 0.0
	}
}

// mapDetectionTypeToFindingType maps DetectionEventType to FindingType.
func mapDetectionTypeToFindingType(eventType DetectionEventType) FindingType {
	switch eventType {
	case DetectionEventTypeAlert:
		return FindingTypeKnownAttackPatternDetected
	case DetectionEventTypeAnomaly:
		return FindingTypeKnownAttackPatternDetected
	case DetectionEventTypeLateralMovement:
		return FindingTypeLateralMovementSuspected
	case DetectionEventTypePolicyViolation:
		return FindingTypeNetworkPolicyViolationDetected
	default:
		return FindingTypeKnownAttackPatternDetected
	}
}
