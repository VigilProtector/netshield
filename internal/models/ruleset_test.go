// Package models contains the data models for NetShield service.
package models

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestRuleSetToAPI(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	objectID, _ := bson.ObjectIDFromHex("507f1f77bcf86cd799439011")
	ruleSet := &RuleSet{
		ID:          objectID,
		Name:        "Test RuleSet",
		Version:     "v1.0",
		Description: "Test Description",
		Enabled:     true,
		Source:      RuleSetSourceETOpen,
		Rules: []RuleRef{
			{RuleID: "rule-001", Enabled: true, Threshold: 1},
			{RuleID: "rule-002", Enabled: false, Threshold: 2},
		},
		Scope: RuleSetScope{
			Type:      ScopeTypeGlobal,
			DefconIDs: []string{"defcon-001", "defcon-002"},
			Namespace: "default",
		},
		IsDefault: false,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: "user-001",
		UpdatedBy: "user-001",
	}

	api := ruleSet.ToAPI()

	if api.ID != "507f1f77bcf86cd799439011" {
		t.Errorf("ToAPI() ID = %v, want %v", api.ID, "507f1f77bcf86cd799439011")
	}
	if api.Name != ruleSet.Name {
		t.Errorf("ToAPI() Name = %v, want %v", api.Name, ruleSet.Name)
	}
	if api.Enabled != ruleSet.Enabled {
		t.Errorf("ToAPI() Enabled = %v, want %v", api.Enabled, ruleSet.Enabled)
	}
	if api.Source != string(ruleSet.Source) {
		t.Errorf("ToAPI() Source = %v, want %v", api.Source, string(ruleSet.Source))
	}
	if len(api.Rules) != len(ruleSet.Rules) {
		t.Errorf("ToAPI() Rules length = %v, want %v", len(api.Rules), len(ruleSet.Rules))
	}
	if api.Scope.Type != string(ruleSet.Scope.Type) {
		t.Errorf("ToAPI() Scope.Type = %v, want %v", api.Scope.Type, string(ruleSet.Scope.Type))
	}
	if api.CreatedAt != now.Format(time.RFC3339) {
		t.Errorf("ToAPI() CreatedAt = %v, want %v", api.CreatedAt, now.Format(time.RFC3339))
	}
}

func TestRuleSetFromAPI(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		api := &RuleSetAPI{
			Name:        "Test RuleSet",
			Version:     "v1.0",
			Description: "Test Description",
			Enabled:     true,
			Source:      "et-open",
			Rules: []RuleRefAPI{
				{RuleID: "rule-001", Enabled: true, Threshold: 1},
				{RuleID: "rule-002", Enabled: false, Threshold: 2},
			},
			Scope: ScopeAPI{
				Type:      "global",
				DefconIDs: []string{"defcon-001", "defcon-002"},
				Namespace: "default",
			},
			IsDefault: false,
			CreatedAt: now.Format(time.RFC3339),
			UpdatedAt: now.Format(time.RFC3339),
			CreatedBy: "user-001",
			UpdatedBy: "user-001",
		}

		ruleSet, err := api.FromAPI()
		if err != nil {
			t.Fatalf("FromAPI() error = %v", err)
		}

		if ruleSet.Name != api.Name {
			t.Errorf("FromAPI() Name = %v, want %v", ruleSet.Name, api.Name)
		}
		if ruleSet.Enabled != api.Enabled {
			t.Errorf("FromAPI() Enabled = %v, want %v", ruleSet.Enabled, api.Enabled)
		}
		if ruleSet.Source != RuleSetSourceETOpen {
			t.Errorf("FromAPI() Source = %v, want %v", ruleSet.Source, RuleSetSourceETOpen)
		}
		if len(ruleSet.Rules) != len(api.Rules) {
			t.Errorf("FromAPI() Rules length = %v, want %v", len(ruleSet.Rules), len(api.Rules))
		}
		if ruleSet.Scope.Type != ScopeTypeGlobal {
			t.Errorf("FromAPI() Scope.Type = %v, want %v", ruleSet.Scope.Type, ScopeTypeGlobal)
		}
	})

	t.Run("invalid createdAt", func(t *testing.T) {
		t.Parallel()

		api := &RuleSetAPI{
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

		api := &RuleSetAPI{
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: "invalid-time",
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid updatedAt, got nil")
		}
	})
}

func TestRuleToAPI(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	objectID, _ := bson.ObjectIDFromHex("507f1f77bcf86cd799439011")
	rule := &Rule{
		ID:        objectID,
		RuleID:    "rule-001",
		Content:   "alert tcp any any -> any any (msg:\"Test\"; sid:1;)",
		Category:  "Malware",
		Severity:  RuleSeverityHigh,
		Message:   "Test Message",
		Reference: "http://example.com",
		Closing:   true,
		Default:   true,
		Source:    RuleSetSourceETOpen,
		CreatedAt: now,
		UpdatedAt: now,
	}

	api := rule.ToAPI()

	if api.ID != "507f1f77bcf86cd799439011" {
		t.Errorf("ToAPI() ID = %v, want %v", api.ID, "507f1f77bcf86cd799439011")
	}
	if api.RuleID != rule.RuleID {
		t.Errorf("ToAPI() RuleID = %v, want %v", api.RuleID, rule.RuleID)
	}
	if api.Content != rule.Content {
		t.Errorf("ToAPI() Content = %v, want %v", api.Content, rule.Content)
	}
	if api.Severity != string(rule.Severity) {
		t.Errorf("ToAPI() Severity = %v, want %v", api.Severity, string(rule.Severity))
	}
	if api.Closing != rule.Closing {
		t.Errorf("ToAPI() Closing = %v, want %v", api.Closing, rule.Closing)
	}
	if api.CreatedAt != now.Format(time.RFC3339) {
		t.Errorf("ToAPI() CreatedAt = %v, want %v", api.CreatedAt, now.Format(time.RFC3339))
	}
}
