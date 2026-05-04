// Package models contains the data models for NetShield service.
package models

import (
	"testing"
	"time"
)

func TestFindingToAPI(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	start := now.Add(-1 * time.Hour)
	end := now
	transitionedAt := now.Add(-30 * time.Minute)
	verifiedAt := now.Add(-15 * time.Minute)
	lastChecked := now
	staleAfter := now.Add(24 * time.Hour)

	finding := &Finding{
		FindingID:   "fnd-001",
		SchemaVersion: "2.0",
		FindingType: FindingTypeKnownAttackPatternDetected,
		SourceContext: "netshield",
		AssetID:     "asset-001",
		DefconID:    "defcon-001",
		OccurredAt:  now,
		Window: &FindingWindow{
			Start: start,
			End:   end,
		},
		Severity:    FindingSeverityHigh,
		Confidence:  0.9,
		Title:       "Test Finding",
		Description: "Test Description",
		Attributes: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
		EvidenceRefs: []EvidenceRef{
			{Type: "type1", Ref: "ref1"},
			{Type: "type2", Ref: "ref2", Hash: "hash1"},
		},
		Correlation: &FindingCorrelation{
			CorrelationID: "corr-001",
		},
		Lifecycle: FindingLifecycle{
			Status:         FindingLifecycleStatusOpen,
			TransitionedAt: &transitionedAt,
			TransitionedBy: "user-001",
			Reason:         "test reason",
		},
		Verification: FindingVerification{
			Status:     FindingVerificationStatusUnverified,
			VerifiedAt: &verifiedAt,
			VerifiedBy: "user-002",
			Method:     "manual",
			Notes:      "test notes",
		},
		Freshness: FindingFreshness{
			Status:      FindingFreshnessStatusFresh,
			StaleAfter:  &staleAfter,
			LastChecked: &lastChecked,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	api := finding.ToAPI()

	if api.FindingID != finding.FindingID {
		t.Errorf("ToAPI() FindingID = %v, want %v", api.FindingID, finding.FindingID)
	}
	if api.SchemaVersion != finding.SchemaVersion {
		t.Errorf("ToAPI() SchemaVersion = %v, want %v", api.SchemaVersion, finding.SchemaVersion)
	}
	if api.FindingType != string(finding.FindingType) {
		t.Errorf("ToAPI() FindingType = %v, want %v", api.FindingType, string(finding.FindingType))
	}
	if api.SourceContext != finding.SourceContext {
		t.Errorf("ToAPI() SourceContext = %v, want %v", api.SourceContext, finding.SourceContext)
	}
	if api.AssetID != finding.AssetID {
		t.Errorf("ToAPI() AssetID = %v, want %v", api.AssetID, finding.AssetID)
	}
	if api.Severity != string(finding.Severity) {
		t.Errorf("ToAPI() Severity = %v, want %v", api.Severity, string(finding.Severity))
	}
	if api.Confidence != finding.Confidence {
		t.Errorf("ToAPI() Confidence = %v, want %v", api.Confidence, finding.Confidence)
	}
	if api.Title != finding.Title {
		t.Errorf("ToAPI() Title = %v, want %v", api.Title, finding.Title)
	}
	if api.Window == nil {
		t.Error("ToAPI() Window should not be nil")
	} else {
		if api.Window.Start != start.Format(time.RFC3339) {
			t.Errorf("ToAPI() Window.Start = %v, want %v", api.Window.Start, start.Format(time.RFC3339))
		}
		if api.Window.End != end.Format(time.RFC3339) {
			t.Errorf("ToAPI() Window.End = %v, want %v", api.Window.End, end.Format(time.RFC3339))
		}
	}
	if len(api.EvidenceRefs) != len(finding.EvidenceRefs) {
		t.Errorf("ToAPI() EvidenceRefs length = %v, want %v", len(api.EvidenceRefs), len(finding.EvidenceRefs))
	}
	if api.Correlation == nil {
		t.Error("ToAPI() Correlation should not be nil")
	} else {
		if api.Correlation.CorrelationID != finding.Correlation.CorrelationID {
			t.Errorf("ToAPI() Correlation.CorrelationID = %v, want %v", api.Correlation.CorrelationID, finding.Correlation.CorrelationID)
		}
	}
	if api.Lifecycle.Status != string(finding.Lifecycle.Status) {
		t.Errorf("ToAPI() Lifecycle.Status = %v, want %v", api.Lifecycle.Status, string(finding.Lifecycle.Status))
	}
}

func TestFindingFromAPI(t *testing.T) {
	t.Parallel()

	t.Run("happy path with all fields", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		start := now.Add(-1 * time.Hour)
		end := now
		transitionedAt := now.Add(-30 * time.Minute)
		verifiedAt := now.Add(-15 * time.Minute)
		lastChecked := now
		staleAfter := now.Add(24 * time.Hour)

		api := &FindingAPI{
			FindingID:     "fnd-001",
			SchemaVersion: "2.0",
			FindingType:   "known_attack_pattern_detected",
			SourceContext: "netshield",
			AssetID:       "asset-001",
			DefconID:      "defcon-001",
			OccurredAt:    now.Format(time.RFC3339),
			Window: &FindingWindowAPI{
				Start: start.Format(time.RFC3339),
				End:   end.Format(time.RFC3339),
			},
			Severity:    "high",
			Confidence:  0.9,
			Title:       "Test Finding",
			Description: "Test Description",
			Attributes: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			EvidenceRefs: []EvidenceRefAPI{
				{Type: "type1", Ref: "ref1"},
				{Type: "type2", Ref: "ref2", Hash: "hash1"},
			},
			Correlation: &FindingCorrelationAPI{
				CorrelationID: "corr-001",
			},
			Lifecycle: FindingLifecycleAPI{
				Status:         "open",
				TransitionedAt: transitionedAt.Format(time.RFC3339),
				TransitionedBy: "user-001",
				Reason:         "test reason",
			},
			Verification: FindingVerificationAPI{
				Status:     "unverified",
				VerifiedAt: verifiedAt.Format(time.RFC3339),
				VerifiedBy: "user-002",
				Method:     "manual",
				Notes:      "test notes",
			},
			Freshness: FindingFreshnessAPI{
				Status:      "fresh",
				StaleAfter:  staleAfter.Format(time.RFC3339),
				LastChecked: lastChecked.Format(time.RFC3339),
			},
			CreatedAt: now.Format(time.RFC3339),
			UpdatedAt: now.Format(time.RFC3339),
		}

		finding, err := api.FromAPI()
		if err != nil {
			t.Fatalf("FromAPI() error = %v", err)
		}

		if finding.FindingID != api.FindingID {
			t.Errorf("FromAPI() FindingID = %v, want %v", finding.FindingID, api.FindingID)
		}
		if finding.SchemaVersion != api.SchemaVersion {
			t.Errorf("FromAPI() SchemaVersion = %v, want %v", finding.SchemaVersion, api.SchemaVersion)
		}
		if finding.FindingType != FindingTypeKnownAttackPatternDetected {
			t.Errorf("FromAPI() FindingType = %v, want %v", finding.FindingType, FindingTypeKnownAttackPatternDetected)
		}
		if finding.SourceContext != api.SourceContext {
			t.Errorf("FromAPI() SourceContext = %v, want %v", finding.SourceContext, api.SourceContext)
		}
		if finding.AssetID != api.AssetID {
			t.Errorf("FromAPI() AssetID = %v, want %v", finding.AssetID, api.AssetID)
		}
		if finding.Severity != FindingSeverityHigh {
			t.Errorf("FromAPI() Severity = %v, want %v", finding.Severity, FindingSeverityHigh)
		}
		if finding.Confidence != api.Confidence {
			t.Errorf("FromAPI() Confidence = %v, want %v", finding.Confidence, api.Confidence)
		}
		if finding.Title != api.Title {
			t.Errorf("FromAPI() Title = %v, want %v", finding.Title, api.Title)
		}
		if finding.Window == nil {
			t.Error("FromAPI() Window should not be nil")
		}
		if finding.Lifecycle.Status != FindingLifecycleStatusOpen {
			t.Errorf("FromAPI() Lifecycle.Status = %v, want %v", finding.Lifecycle.Status, FindingLifecycleStatusOpen)
		}
	})

	t.Run("invalid occurredAt", func(t *testing.T) {
		t.Parallel()

		api := &FindingAPI{
			OccurredAt: "invalid-time",
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid occurredAt, got nil")
		}
	})

	t.Run("invalid createdAt", func(t *testing.T) {
		t.Parallel()

		api := &FindingAPI{
			OccurredAt: time.Now().Format(time.RFC3339),
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

		api := &FindingAPI{
			OccurredAt: time.Now().Format(time.RFC3339),
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: "invalid-time",
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid updatedAt, got nil")
		}
	})
}
