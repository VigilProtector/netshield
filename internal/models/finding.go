// Package models contains the data models for NetShield service.
// This file implements Finding Contract v2 compatible models.
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// FindingContractVersion is the version of the finding contract implemented.
const FindingContractVersion = "2.0"

// Finding represents a security finding emitted by NetShield.
// Implements Finding Contract v2 as specified in VL-FC-001.
type Finding struct {
	ID            bson.ObjectID       `bson:"_id,omitempty" json:"-"`
	FindingID     string              `bson:"findingId" json:"findingId"`
	SchemaVersion string              `bson:"schemaVersion" json:"schemaVersion"`
	FindingType   FindingType         `bson:"findingType" json:"findingType"`
	SourceContext string              `bson:"sourceContext" json:"sourceContext"`
	AssetID       string              `bson:"assetId,omitempty" json:"assetId,omitempty"`
	DefconID      string              `bson:"defconId,omitempty" json:"defconId,omitempty"`
	OccurredAt    time.Time           `bson:"occurredAt" json:"occurredAt"`
	Window        *FindingWindow      `bson:"window,omitempty" json:"window,omitempty"`
	Severity      FindingSeverity     `bson:"severity" json:"severity"`
	Confidence    float64             `bson:"confidence" json:"confidence"`
	Title         string              `bson:"title" json:"title"`
	Description   string              `bson:"description,omitempty" json:"description,omitempty"`
	Attributes    map[string]string   `bson:"attributes,omitempty" json:"attributes,omitempty"`
	EvidenceRefs  []EvidenceRef       `bson:"evidenceRefs" json:"evidenceRefs"`
	Correlation   *FindingCorrelation `bson:"correlation,omitempty" json:"correlation,omitempty"`
	Lifecycle     FindingLifecycle    `bson:"lifecycle" json:"lifecycle"`
	Verification  FindingVerification `bson:"verification" json:"verification"`
	Freshness     FindingFreshness    `bson:"freshness" json:"freshness"`
	CreatedAt     time.Time           `bson:"createdAt" json:"createdAt"`
	UpdatedAt     time.Time           `bson:"updatedAt" json:"updatedAt"`
}

// FindingAPI represents a finding for API responses.
type FindingAPI struct {
	FindingID     string                 `json:"findingId"`
	SchemaVersion string                 `json:"schemaVersion"`
	FindingType   string                 `json:"findingType"`
	SourceContext string                 `json:"sourceContext"`
	AssetID       string                 `json:"assetId,omitempty"`
	DefconID      string                 `json:"defconId,omitempty"`
	OccurredAt    string                 `json:"occurredAt"`
	Window        *FindingWindowAPI      `json:"window,omitempty"`
	Severity      string                 `json:"severity"`
	Confidence    float64                `json:"confidence"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description,omitempty"`
	Attributes    map[string]string      `json:"attributes,omitempty"`
	EvidenceRefs  []EvidenceRefAPI       `json:"evidenceRefs"`
	Correlation   *FindingCorrelationAPI `json:"correlation,omitempty"`
	Lifecycle     FindingLifecycleAPI    `json:"lifecycle"`
	Verification  FindingVerificationAPI `json:"verification"`
	Freshness     FindingFreshnessAPI    `json:"freshness"`
	CreatedAt     string                 `json:"createdAt"`
	UpdatedAt     string                 `json:"updatedAt"`
}

// FindingListResponse wraps a list of findings for API responses.
type FindingListResponse struct {
	Items      []*Finding `json:"items"`
	TotalCount int        `json:"totalCount"`
	Limit      int        `json:"limit"`
	Offset     int        `json:"offset"`
}

// FindingType represents the type of finding.
type FindingType string

const (
	// FindingTypeKnownAttackPatternDetected indicates detection of a known attack pattern.
	// Implements NH-FD-*: Core-Findings produktiv.
	FindingTypeKnownAttackPatternDetected FindingType = "known_attack_pattern_detected"
	// FindingTypeLateralMovementSuspected indicates suspected lateral movement.
	// Implements NH-LM-007: Emission network.lateral_movement_suspected.
	FindingTypeLateralMovementSuspected FindingType = "network.lateral_movement_suspected"
	// FindingTypeNetworkPolicyViolationDetected indicates detection of a network policy violation.
	FindingTypeNetworkPolicyViolationDetected FindingType = "network_policy_violation_detected"
	// FindingTypeConfigDriftUnauthorized indicates unauthorized configuration drift.
	FindingTypeConfigDriftUnauthorized FindingType = "config_drift_unauthorized"
	// FindingTypeConfigBaselineMissing indicates missing configuration baseline.
	FindingTypeConfigBaselineMissing FindingType = "config_baseline_missing"
)

// FindingSeverity represents the severity of a finding.
type FindingSeverity string

const (
	// FindingSeverityCritical indicates critical severity.
	FindingSeverityCritical FindingSeverity = "critical"
	// FindingSeverityHigh indicates high severity.
	FindingSeverityHigh FindingSeverity = "high"
	// FindingSeverityMedium indicates medium severity.
	FindingSeverityMedium FindingSeverity = "medium"
	// FindingSeverityLow indicates low severity.
	FindingSeverityLow FindingSeverity = "low"
	// FindingSeverityInfo indicates informational severity.
	FindingSeverityInfo FindingSeverity = "info"
)

// FindingWindow represents the time window for a finding.
type FindingWindow struct {
	Start time.Time `bson:"start" json:"start"`
	End   time.Time `bson:"end" json:"end"`
}

// FindingWindowAPI represents a finding window for API responses.
type FindingWindowAPI struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// EvidenceRef represents a reference to evidence for a finding.
type EvidenceRef struct {
	Type string `bson:"type" json:"type"`
	Ref  string `bson:"ref" json:"ref"`
	Hash string `bson:"hash,omitempty" json:"hash,omitempty"`
}

// EvidenceRefAPI represents an evidence reference for API responses.
type EvidenceRefAPI struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
	Hash string `json:"hash,omitempty"`
}

// FindingCorrelation represents correlation information for a finding.
type FindingCorrelation struct {
	CorrelationID string `bson:"correlationId" json:"correlationId"`
}

// FindingCorrelationAPI represents correlation for API responses.
type FindingCorrelationAPI struct {
	CorrelationID string `json:"correlationId"`
}

// FindingLifecycle represents the lifecycle of a finding.
// Implements VL-FC-001: Basis-Lifecycle open -> resolved -> closed.
type FindingLifecycle struct {
	Status         FindingLifecycleStatus `bson:"status" json:"status"`
	TransitionedAt *time.Time             `bson:"transitionedAt,omitempty" json:"transitionedAt,omitempty"`
	TransitionedBy string                 `bson:"transitionedBy,omitempty" json:"transitionedBy,omitempty"`
	Reason         string                 `bson:"reason,omitempty" json:"reason,omitempty"`
}

// FindingLifecycleAPI represents lifecycle for API responses.
type FindingLifecycleAPI struct {
	Status         string `json:"status"`
	TransitionedAt string `json:"transitionedAt,omitempty"`
	TransitionedBy string `json:"transitionedBy,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// FindingLifecycleStatus represents the status of a finding lifecycle.
type FindingLifecycleStatus string

const (
	// FindingLifecycleStatusOpen indicates the finding is open.
	FindingLifecycleStatusOpen FindingLifecycleStatus = "open"
	// FindingLifecycleStatusResolved indicates the finding has been resolved.
	FindingLifecycleStatusResolved FindingLifecycleStatus = "resolved"
	// FindingLifecycleStatusClosed indicates the finding has been closed.
	FindingLifecycleStatusClosed FindingLifecycleStatus = "closed"
)

// FindingVerification represents verification information for a finding.
type FindingVerification struct {
	Status     FindingVerificationStatus `bson:"status" json:"status"`
	VerifiedAt *time.Time                `bson:"verifiedAt,omitempty" json:"verifiedAt,omitempty"`
	VerifiedBy string                    `bson:"verifiedBy,omitempty" json:"verifiedBy,omitempty"`
	Method     string                    `bson:"method,omitempty" json:"method,omitempty"`
	Notes      string                    `bson:"notes,omitempty" json:"notes,omitempty"`
}

// FindingVerificationAPI represents verification for API responses.
type FindingVerificationAPI struct {
	Status     string `json:"status"`
	VerifiedAt string `json:"verifiedAt,omitempty"`
	VerifiedBy string `json:"verifiedBy,omitempty"`
	Method     string `json:"method,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// FindingVerificationStatus represents the verification status of a finding.
type FindingVerificationStatus string

const (
	// FindingVerificationStatusUnverified indicates the finding is unverified.
	FindingVerificationStatusUnverified FindingVerificationStatus = "unverified"
	// FindingVerificationStatusVerified indicates the finding is verified.
	FindingVerificationStatusVerified FindingVerificationStatus = "verified"
	// FindingVerificationStatusFalsePositive indicates the finding is a false positive.
	FindingVerificationStatusFalsePositive FindingVerificationStatus = "false_positive"
)

// FindingFreshness represents freshness information for a finding.
type FindingFreshness struct {
	Status      FindingFreshnessStatus `bson:"status" json:"status"`
	StaleAfter  *time.Time             `bson:"staleAfter,omitempty" json:"staleAfter,omitempty"`
	LastChecked *time.Time             `bson:"lastChecked,omitempty" json:"lastChecked,omitempty"`
}

// FindingFreshnessAPI represents freshness for API responses.
type FindingFreshnessAPI struct {
	Status      string `json:"status"`
	StaleAfter  string `json:"staleAfter,omitempty"`
	LastChecked string `json:"lastChecked,omitempty"`
}

// FindingFreshnessStatus represents the freshness status of a finding.
type FindingFreshnessStatus string

const (
	// FindingFreshnessStatusFresh indicates the finding is fresh.
	FindingFreshnessStatusFresh FindingFreshnessStatus = "fresh"
	// FindingFreshnessStatusStale indicates the finding is stale.
	FindingFreshnessStatusStale FindingFreshnessStatus = "stale"
)

// FindingFilter defines filter options for listing findings.
type FindingFilter struct {
	FindingType   string `json:"findingType,omitempty"`
	SourceContext string `json:"sourceContext,omitempty"`
	AssetID       string `json:"assetId,omitempty"`
	DefconID      string `json:"defconId,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Lifecycle     string `json:"lifecycle,omitempty"`
	Verification  string `json:"verification,omitempty"`
	Freshness     string `json:"freshness,omitempty"`
	StartTime     string `json:"startTime,omitempty"`
	EndTime       string `json:"endTime,omitempty"`
}

// ListFindingsOptions defines options for listing findings.
type ListFindingsOptions struct {
	Filter  FindingFilter `json:"filter,omitempty"`
	Limit   int           `json:"limit,omitempty"`
	Offset  int           `json:"offset,omitempty"`
	SortBy  string        `json:"sortBy,omitempty"`
	SortAsc bool          `json:"sortAsc,omitempty"`
}

// UpdateFindingLifecycleRequest represents a request to update finding lifecycle.
type UpdateFindingLifecycleRequest struct {
	Status         FindingLifecycleStatus `json:"status"`
	Reason         string                 `json:"reason,omitempty"`
	TransitionedBy string                 `json:"transitionedBy,omitempty"`
}

// UpdateFindingVerificationRequest represents a request to update finding verification.
type UpdateFindingVerificationRequest struct {
	Status     FindingVerificationStatus `json:"status"`
	Method     string                    `json:"method,omitempty"`
	Notes      string                    `json:"notes,omitempty"`
	VerifiedBy string                    `json:"verifiedBy,omitempty"`
}

// ToAPI converts a Finding to a FindingAPI.
func (f *Finding) ToAPI() *FindingAPI {
	window := (*FindingWindowAPI)(nil)
	if f.Window != nil {
		window = &FindingWindowAPI{
			Start: f.Window.Start.Format(time.RFC3339),
			End:   f.Window.End.Format(time.RFC3339),
		}
	}

	evidenceRefs := make([]EvidenceRefAPI, len(f.EvidenceRefs))
	for i, ref := range f.EvidenceRefs {
		//nolint:staticcheck // direct struct literal is clearer than conversion function
		evidenceRefs[i] = EvidenceRefAPI{
			Type: ref.Type,
			Ref:  ref.Ref,
			Hash: ref.Hash,
		}
	}

	transitionedAt := ""
	if f.Lifecycle.TransitionedAt != nil {
		transitionedAt = f.Lifecycle.TransitionedAt.Format(time.RFC3339)
	}

	verifiedAt := ""
	if f.Verification.VerifiedAt != nil {
		verifiedAt = f.Verification.VerifiedAt.Format(time.RFC3339)
	}

	lastChecked := ""
	if f.Freshness.LastChecked != nil {
		lastChecked = f.Freshness.LastChecked.Format(time.RFC3339)
	}

	staleAfter := ""
	if f.Freshness.StaleAfter != nil {
		staleAfter = f.Freshness.StaleAfter.Format(time.RFC3339)
	}

	correlation := (*FindingCorrelationAPI)(nil)
	if f.Correlation != nil {
		correlation = &FindingCorrelationAPI{
			CorrelationID: f.Correlation.CorrelationID,
		}
	}

	return &FindingAPI{
		FindingID:     f.FindingID,
		SchemaVersion: f.SchemaVersion,
		FindingType:   string(f.FindingType),
		SourceContext: f.SourceContext,
		AssetID:       f.AssetID,
		DefconID:      f.DefconID,
		OccurredAt:    f.OccurredAt.Format(time.RFC3339),
		Window:        window,
		Severity:      string(f.Severity),
		Confidence:    f.Confidence,
		Title:         f.Title,
		Description:   f.Description,
		Attributes:    f.Attributes,
		EvidenceRefs:  evidenceRefs,
		Correlation:   correlation,
		Lifecycle: FindingLifecycleAPI{
			Status:         string(f.Lifecycle.Status),
			TransitionedAt: transitionedAt,
			TransitionedBy: f.Lifecycle.TransitionedBy,
			Reason:         f.Lifecycle.Reason,
		},
		Verification: FindingVerificationAPI{
			Status:     string(f.Verification.Status),
			VerifiedAt: verifiedAt,
			VerifiedBy: f.Verification.VerifiedBy,
			Method:     f.Verification.Method,
			Notes:      f.Verification.Notes,
		},
		Freshness: FindingFreshnessAPI{
			Status:      string(f.Freshness.Status),
			StaleAfter:  staleAfter,
			LastChecked: lastChecked,
		},
		CreatedAt: f.CreatedAt.Format(time.RFC3339),
		UpdatedAt: f.UpdatedAt.Format(time.RFC3339),
	}
}

// FromAPI converts a FindingAPI to a Finding.
func (f *FindingAPI) FromAPI() (*Finding, error) {
	occurredAt, err := time.Parse(time.RFC3339, f.OccurredAt)
	if err != nil {
		return nil, err
	}

	createdAt, err := time.Parse(time.RFC3339, f.CreatedAt)
	if err != nil {
		return nil, err
	}

	updatedAt, err := time.Parse(time.RFC3339, f.UpdatedAt)
	if err != nil {
		return nil, err
	}

	var window *FindingWindow

	if f.Window != nil {
		start, err := time.Parse(time.RFC3339, f.Window.Start)
		if err != nil {
			return nil, err
		}

		end, err := time.Parse(time.RFC3339, f.Window.End)
		if err != nil {
			return nil, err
		}

		window = &FindingWindow{
			Start: start,
			End:   end,
		}
	}

	evidenceRefs := make([]EvidenceRef, len(f.EvidenceRefs))
	for i, ref := range f.EvidenceRefs {
		//nolint:staticcheck // direct struct literal is clearer than conversion function
		evidenceRefs[i] = EvidenceRef{
			Type: ref.Type,
			Ref:  ref.Ref,
			Hash: ref.Hash,
		}
	}

	var transitionedAt *time.Time

	if f.Lifecycle.TransitionedAt != "" {
		t, err := time.Parse(time.RFC3339, f.Lifecycle.TransitionedAt)
		if err != nil {
			return nil, err
		}

		transitionedAt = &t
	}

	var verifiedAt *time.Time

	if f.Verification.VerifiedAt != "" {
		t, err := time.Parse(time.RFC3339, f.Verification.VerifiedAt)
		if err != nil {
			return nil, err
		}

		verifiedAt = &t
	}

	var lastChecked *time.Time

	if f.Freshness.LastChecked != "" {
		t, err := time.Parse(time.RFC3339, f.Freshness.LastChecked)
		if err != nil {
			return nil, err
		}

		lastChecked = &t
	}

	var staleAfter *time.Time

	if f.Freshness.StaleAfter != "" {
		t, err := time.Parse(time.RFC3339, f.Freshness.StaleAfter)
		if err != nil {
			return nil, err
		}

		staleAfter = &t
	}

	var correlation *FindingCorrelation
	if f.Correlation != nil {
		correlation = &FindingCorrelation{
			CorrelationID: f.Correlation.CorrelationID,
		}
	}

	return &Finding{
		FindingID:     f.FindingID,
		SchemaVersion: f.SchemaVersion,
		FindingType:   FindingType(f.FindingType),
		SourceContext: f.SourceContext,
		AssetID:       f.AssetID,
		DefconID:      f.DefconID,
		OccurredAt:    occurredAt,
		Window:        window,
		Severity:      FindingSeverity(f.Severity),
		Confidence:    f.Confidence,
		Title:         f.Title,
		Description:   f.Description,
		Attributes:    f.Attributes,
		EvidenceRefs:  evidenceRefs,
		Correlation:   correlation,
		Lifecycle: FindingLifecycle{
			Status:         FindingLifecycleStatus(f.Lifecycle.Status),
			TransitionedAt: transitionedAt,
			TransitionedBy: f.Lifecycle.TransitionedBy,
			Reason:         f.Lifecycle.Reason,
		},
		Verification: FindingVerification{
			Status:     FindingVerificationStatus(f.Verification.Status),
			VerifiedAt: verifiedAt,
			VerifiedBy: f.Verification.VerifiedBy,
			Method:     f.Verification.Method,
			Notes:      f.Verification.Notes,
		},
		Freshness: FindingFreshness{
			Status:      FindingFreshnessStatus(f.Freshness.Status),
			StaleAfter:  staleAfter,
			LastChecked: lastChecked,
		},
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}
