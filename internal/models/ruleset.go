// Package models contains the data models for NetShield service.
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// RuleSet represents a collection of Suricata rules.
// Implements NH-RD-001..007: Regelset-Datenmodell, ET Open Baseline, Regelset-Management-APIs, Regelset-Rendering.
type RuleSet struct {
	ID          bson.ObjectID `bson:"_id,omitempty" json:"-"`
	Name        string        `bson:"name" json:"name"`
	Version     string        `bson:"version" json:"version"`
	Description string        `bson:"description" json:"description"`
	Enabled     bool          `bson:"enabled" json:"enabled"`
	Source      RuleSetSource `bson:"source" json:"source"`
	Rules       []RuleRef     `bson:"rules" json:"rules"`
	Scope       RuleSetScope  `bson:"scope" json:"scope"`
	// IsDefault indicates if this rule set is the default for new sensors.
	// NH-RD-002: ET Open Baseline should be marked as default.
	IsDefault bool      `bson:"isDefault" json:"isDefault"`
	CreatedAt time.Time `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time `bson:"updatedAt" json:"updatedAt"`
	CreatedBy string    `bson:"createdBy" json:"createdBy"`
	UpdatedBy string    `bson:"updatedBy" json:"updatedBy"`
}

// RuleSetAPI represents a rule set for API responses.
type RuleSetAPI struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description,omitempty"`
	Enabled     bool         `json:"enabled"`
	Source      string       `json:"source"`
	Rules       []RuleRefAPI `json:"rules"`
	Scope       ScopeAPI     `json:"scope"`
	IsDefault   bool         `json:"isDefault"`
	CreatedAt   string       `json:"createdAt"`
	UpdatedAt   string       `json:"updatedAt"`
	CreatedBy   string       `json:"createdBy"`
	UpdatedBy   string       `json:"updatedBy"`
}

// RuleSetListResponse wraps a list of rule sets for API responses.
type RuleSetListResponse struct {
	Items      []*RuleSet `json:"items"`
	TotalCount int        `json:"totalCount"`
	Limit      int        `json:"limit"`
	Offset     int        `json:"offset"`
}

// RuleSetSource represents the source of a rule set.
type RuleSetSource string

const (
	// RuleSetSourceETOpen indicates rules from Emerging Threats Open.
	RuleSetSourceETOpen RuleSetSource = "et-open"
	// RuleSetSourceETPro indicates rules from Emerging Threats Pro.
	RuleSetSourceETPro RuleSetSource = "et-pro"
	// RuleSetSourceCustom indicates custom user-defined rules.
	RuleSetSourceCustom RuleSetSource = "custom"
)

// RuleSetScope represents the scope of a rule set.
type RuleSetScope struct {
	Type      ScopeType `bson:"type" json:"type"`
	DefconIDs []string  `bson:"defconIds,omitempty" json:"defconIds,omitempty"`
	Namespace string    `bson:"namespace,omitempty" json:"namespace,omitempty"`
}

// ScopeType represents the type of scope.
type ScopeType string

const (
	// ScopeTypeGlobal indicates the rule set applies to all Defcons.
	ScopeTypeGlobal ScopeType = "global"
	// ScopeTypeDefconSpecific indicates the rule set applies to specific Defcons.
	ScopeTypeDefconSpecific ScopeType = "defcon-specific"
	// ScopeTypeNamespaceSpecific indicates the rule set applies to a specific namespace.
	ScopeTypeNamespaceSpecific ScopeType = "namespace-specific"
)

// ScopeAPI represents scope for API responses.
type ScopeAPI struct {
	Type      string   `json:"type"`
	DefconIDs []string `json:"defconIds,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
}

// RuleRef represents a reference to a rule in a rule set.
type RuleRef struct {
	RuleID    string `bson:"ruleId" json:"ruleId"`
	Enabled   bool   `bson:"enabled" json:"enabled"`
	Threshold int    `bson:"threshold,omitempty" json:"threshold,omitempty"` // For threshold-based rules
}

// RuleRefAPI represents a rule reference for API responses.
type RuleRefAPI struct {
	RuleID    string `json:"ruleId"`
	Enabled   bool   `json:"enabled"`
	Threshold int    `json:"threshold,omitempty"`
}

// Rule represents a single Suricata rule.
type Rule struct {
	ID        bson.ObjectID `bson:"_id,omitempty" json:"-"`
	RuleID    string        `bson:"ruleId" json:"ruleId"`
	Content   string        `bson:"content" json:"content"`
	Category  string        `bson:"category" json:"category"`
	Severity  RuleSeverity  `bson:"severity" json:"severity"`
	Message   string        `bson:"message" json:"message"`
	Reference string        `bson:"reference,omitempty" json:"reference,omitempty"`
	Closing   bool          `bson:"closing,omitempty" json:"closing,omitempty"`
	Default   bool          `bson:"default,omitempty" json:"default,omitempty"`
	Source    RuleSetSource `bson:"source" json:"source"`
	CreatedAt time.Time     `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time     `bson:"updatedAt" json:"updatedAt"`
	CreatedBy string        `bson:"createdBy" json:"createdBy"`
	UpdatedBy string        `bson:"updatedBy" json:"updatedBy"`
}

// RuleAPI represents a rule for API responses.
type RuleAPI struct {
	ID        string `json:"id"`
	RuleID    string `json:"ruleId"`
	Content   string `json:"content"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Reference string `json:"reference,omitempty"`
	Closing   bool   `json:"closing,omitempty"`
	Default   bool   `json:"default,omitempty"`
	Source    string `json:"source"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// RuleSeverity represents the severity of a rule.
type RuleSeverity string

const (
	// RuleSeverityCritical indicates critical severity.
	RuleSeverityCritical RuleSeverity = "critical"
	// RuleSeverityHigh indicates high severity.
	RuleSeverityHigh RuleSeverity = "high"
	// RuleSeverityMedium indicates medium severity.
	RuleSeverityMedium RuleSeverity = "medium"
	// RuleSeverityLow indicates low severity.
	RuleSeverityLow RuleSeverity = "low"
	// RuleSeverityInformational indicates informational severity.
	RuleSeverityInformational RuleSeverity = "informational"
)

// RuleListResponse wraps a list of rules for API responses.
type RuleListResponse struct {
	Items      []*Rule `json:"items"`
	TotalCount int     `json:"totalCount"`
	Limit      int     `json:"limit"`
	Offset     int     `json:"offset"`
}

// RuleFilter defines filter options for listing rules.
type RuleFilter struct {
	RuleID   string `json:"ruleId,omitempty"`
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	Source   string `json:"source,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
}

// ListRulesOptions defines options for listing rules.
type ListRulesOptions struct {
	Filter  RuleFilter `json:"filter,omitempty"`
	Limit   int        `json:"limit,omitempty"`
	Offset  int        `json:"offset,omitempty"`
	SortBy  string     `json:"sortBy,omitempty"`
	SortAsc bool       `json:"sortAsc,omitempty"`
}

// CreateRuleSetRequest represents a request to create a rule set.
type CreateRuleSetRequest struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description,omitempty"`
	Enabled     bool         `json:"enabled"`
	Source      string       `json:"source"`
	Rules       []RuleRefAPI `json:"rules"`
	Scope       ScopeAPI     `json:"scope"`
}

// UpdateRuleSetRequest represents a request to update a rule set.
type UpdateRuleSetRequest struct {
	Name        string       `json:"name,omitempty"`
	Version     string       `json:"version,omitempty"`
	Description string       `json:"description,omitempty"`
	Enabled     *bool        `json:"enabled,omitempty"`
	Source      string       `json:"source,omitempty"`
	Rules       []RuleRefAPI `json:"rules,omitempty"`
	Scope       ScopeAPI     `json:"scope,omitempty"`
}

// RuleSetFilter defines filter options for listing rule sets.
type RuleSetFilter struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// ToAPI converts a RuleSet to a RuleSetAPI.
func (r *RuleSet) ToAPI() *RuleSetAPI {
	rules := make([]RuleRefAPI, len(r.Rules))
	for i, rule := range r.Rules {
		//nolint:gosimple // direct struct literal is clearer than conversion function
		rules[i] = RuleRefAPI{
			RuleID:    rule.RuleID,
			Enabled:   rule.Enabled,
			Threshold: rule.Threshold,
		}
	}

	defconIDs := make([]string, len(r.Scope.DefconIDs))
	copy(defconIDs, r.Scope.DefconIDs)

	return &RuleSetAPI{
		ID:          r.ID.Hex(),
		Name:        r.Name,
		Version:     r.Version,
		Description: r.Description,
		Enabled:     r.Enabled,
		Source:      string(r.Source),
		Rules:       rules,
		Scope: ScopeAPI{
			Type:      string(r.Scope.Type),
			DefconIDs: defconIDs,
			Namespace: r.Scope.Namespace,
		},
		IsDefault: r.IsDefault,
		CreatedAt: r.CreatedAt.Format(time.RFC3339),
		UpdatedAt: r.UpdatedAt.Format(time.RFC3339),
		CreatedBy: r.CreatedBy,
		UpdatedBy: r.UpdatedBy,
	}
}

// FromAPI converts a RuleSetAPI to a RuleSet.
func (r *RuleSetAPI) FromAPI() (*RuleSet, error) {
	createdAt, err := time.Parse(time.RFC3339, r.CreatedAt)
	if err != nil {
		return nil, err
	}

	updatedAt, err := time.Parse(time.RFC3339, r.UpdatedAt)
	if err != nil {
		return nil, err
	}

	rules := make([]RuleRef, len(r.Rules))
	for i, rule := range r.Rules {
		//nolint:gosimple // direct struct literal is clearer than conversion function
		rules[i] = RuleRef{
			RuleID:    rule.RuleID,
			Enabled:   rule.Enabled,
			Threshold: rule.Threshold,
		}
	}

	return &RuleSet{
		Name:        r.Name,
		Version:     r.Version,
		Description: r.Description,
		Enabled:     r.Enabled,
		Source:      RuleSetSource(r.Source),
		Rules:       rules,
		Scope: RuleSetScope{
			Type:      ScopeType(r.Scope.Type),
			DefconIDs: r.Scope.DefconIDs,
			Namespace: r.Scope.Namespace,
		},
		IsDefault: r.IsDefault,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		CreatedBy: r.CreatedBy,
		UpdatedBy: r.UpdatedBy,
	}, nil
}

// ToAPI converts a Rule to a RuleAPI.
func (r *Rule) ToAPI() *RuleAPI {
	return &RuleAPI{
		ID:        r.ID.Hex(),
		RuleID:    r.RuleID,
		Content:   r.Content,
		Category:  r.Category,
		Severity:  string(r.Severity),
		Message:   r.Message,
		Reference: r.Reference,
		Closing:   r.Closing,
		Default:   r.Default,
		Source:    string(r.Source),
		CreatedAt: r.CreatedAt.Format(time.RFC3339),
		UpdatedAt: r.UpdatedAt.Format(time.RFC3339),
	}
}
