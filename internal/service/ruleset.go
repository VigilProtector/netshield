// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/vp-lib/authz"
	"vigilprotector.io/vp-lib/correlation"
	"vigilprotector.io/vp-lib/ironchronicle"
	vplogging "vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// Errors for the ruleset service.
var (
	// ErrRuleSetNotFound is returned when a rule set is not found.
	ErrRuleSetNotFound = errors.New("rule set not found")
	// ErrRuleSetAlreadyExists is returned when a rule set already exists.
	ErrRuleSetAlreadyExists = errors.New("rule set already exists")
	// ErrDefaultRuleSetCannotDelete is returned when trying to delete the default rule set.
	ErrDefaultRuleSetCannotDelete = errors.New("cannot delete default rule set")
	// ErrDefaultRuleSetCannotDisable is returned when trying to disable the default rule set.
	ErrDefaultRuleSetCannotDisable = errors.New("cannot disable default rule set")
	// ErrInvalidSource is returned when an invalid source is provided.
	ErrInvalidSource = errors.New("invalid rule set source")
	// ErrInvalidScopeType is returned when an invalid scope type is provided.
	ErrInvalidScopeType = errors.New("invalid scope type")
)

// RuleSetStorer defines the interface for ruleset persistence operations.
// Consumer-defined interface pattern: defined where consumed (service layer).
type RuleSetStorer interface {
	// List returns a paginated list of rule sets with optional filtering.
	List(ctx context.Context, opts models.RuleSetFilter) (*models.RuleSetListResponse, error)
	// GetByID returns a single rule set by its ID.
	GetByID(ctx context.Context, id string) (*models.RuleSet, error)
	// GetByName returns a single rule set by its name.
	GetByName(ctx context.Context, name string) (*models.RuleSet, error)
	// GetDefault returns the default rule set (ET Open Baseline).
	GetDefault(ctx context.Context) (*models.RuleSet, error)
	// Create creates a new rule set.
	Create(ctx context.Context, ruleset *models.RuleSet) error
	// Update updates an existing rule set.
	Update(ctx context.Context, ruleset *models.RuleSet) error
	// Delete deletes a rule set by its ID.
	Delete(ctx context.Context, id string) error
	// GetByScope returns rule sets that apply to a specific scope.
	GetByScope(ctx context.Context, scopeType models.ScopeType, defconID, namespace string) ([]*models.RuleSet, error)
}

// RuleStorer defines the interface for rule persistence operations.
// Consumer-defined interface pattern: defined where consumed (service layer).
type RuleStorer interface {
	// List returns a paginated list of rules with optional filtering.
	List(ctx context.Context, opts models.ListRulesOptions) (*models.RuleListResponse, error)
	// GetByID returns a single rule by its ID.
	GetByID(ctx context.Context, id string) (*models.Rule, error)
	// GetByRuleID returns a single rule by its rule ID.
	GetByRuleID(ctx context.Context, ruleID string) (*models.Rule, error)
	// Create creates a new rule.
	Create(ctx context.Context, rule *models.Rule) error
	// Update updates an existing rule.
	Update(ctx context.Context, rule *models.Rule) error
	// Delete deletes a rule by its ID.
	Delete(ctx context.Context, id string) error
	// GetByRuleIDs returns multiple rules by their rule IDs.
	GetByRuleIDs(ctx context.Context, ruleIDs []string) ([]*models.Rule, error)
}

// RuleSetServiceInterface defines the interface for ruleset service operations.
// This is the public interface that handlers consume.
// Consumer-defined interface pattern: defined where consumed (handler layer).
type RuleSetServiceInterface interface {
	// List returns a paginated list of rule sets with optional filtering.
	List(ctx context.Context, logger logr.Logger, subject *types.Subject, filter models.RuleSetFilter) (*models.RuleSetListResponse, error)
	// Get returns a single rule set by its ID.
	Get(ctx context.Context, logger logr.Logger, subject *types.Subject, id string) (*models.RuleSet, error)
	// Create creates a new rule set.
	Create(ctx context.Context, logger logr.Logger, subject *types.Subject, req models.CreateRuleSetRequest) (*models.RuleSet, error)
	// Update updates an existing rule set.
	Update(ctx context.Context, logger logr.Logger, subject *types.Subject, id string, req models.UpdateRuleSetRequest) (*models.RuleSet, error)
	// Delete deletes a rule set by its ID.
	Delete(ctx context.Context, logger logr.Logger, subject *types.Subject, id string) error
	// Enable enables a rule set.
	Enable(ctx context.Context, logger logr.Logger, subject *types.Subject, id string) (*models.RuleSet, error)
	// Disable disables a rule set.
	Disable(ctx context.Context, logger logr.Logger, subject *types.Subject, id string) (*models.RuleSet, error)
	// GetDefault returns the default rule set (ET Open Baseline).
	GetDefault(ctx context.Context, logger logr.Logger, subject *types.Subject) (*models.RuleSet, error)
	// Render renders a rule set into Suricata-compatible format.
	Render(ctx context.Context, logger logr.Logger, subject *types.Subject, id string) (string, error)
}

// RuleSetService implements business logic for ruleset operations.
type RuleSetService struct {
	ruleSetStore RuleSetStorer
	ruleStore    RuleStorer
	logger       logr.Logger
}

// NewRuleSetService creates a new RuleSetService.
func NewRuleSetService(
	ruleSetStore RuleSetStorer,
	ruleStore RuleStorer,
	logger logr.Logger,
) *RuleSetService {
	return &RuleSetService{
		ruleSetStore: ruleSetStore,
		ruleStore:    ruleStore,
		logger:       logger,
	}
}

// Verify that RuleSetService implements RuleSetServiceInterface.
var _ RuleSetServiceInterface = (*RuleSetService)(nil)

// List returns a paginated list of rule sets with optional filtering.
// Implements NH-RD-003: Regelset-Management-APIs.
func (s *RuleSetService) List(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	filter models.RuleSetFilter,
) (*models.RuleSetListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("listing rule sets",
		"filter.name", filter.Name,
		"filter.version", filter.Version,
		"filter.source", filter.Source,
		"filter.enabled", filter.Enabled)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  "*",
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	response, err := s.ruleSetStore.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list rule sets from store: %w", err)
	}

	return response, nil
}

// Get returns a single rule set by its ID.
// Implements NH-RD-003: Regelset-Management-APIs.
func (s *RuleSetService) Get(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	id string,
) (*models.RuleSet, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting rule set by id", "id", id)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.read",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  id,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	ruleSet, err := s.ruleSetStore.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule set from store: %w", err)
	}

	if ruleSet == nil {
		return nil, ErrRuleSetNotFound
	}

	return ruleSet, nil
}

// Create creates a new rule set.
// Implements NH-RD-003: Regelset-Management-APIs.
// Emits audit event per NH-RD-011.
func (s *RuleSetService) Create(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	req models.CreateRuleSetRequest,
) (*models.RuleSet, error) {
	logger.V(vplogging.LogLevelVerbose).Info("creating rule set",
		"name", req.Name,
		"version", req.Version,
		"source", req.Source)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.create",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  "*",
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	// Validate required fields
	if req.Name == "" {
		return nil, fmt.Errorf("name is required: %w", ErrInvalidSource)
	}

	// Validate source
	source := models.RuleSetSource(req.Source)
	if source != models.RuleSetSourceETOpen &&
		source != models.RuleSetSourceETPro &&
		source != models.RuleSetSourceCustom {
		return nil, fmt.Errorf("invalid source %q: %w", req.Source, ErrInvalidSource)
	}

	// Check if rule set already exists
	existing, err := s.ruleSetStore.GetByName(ctx, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing rule set: %w", err)
	}

	if existing != nil {
		return nil, ErrRuleSetAlreadyExists
	}

	// Convert scope from API to domain model
	scope := models.RuleSetScope{
		Type:      models.ScopeType(req.Scope.Type),
		DefconIDs: req.Scope.DefconIDs,
		Namespace: req.Scope.Namespace,
	}

	// Convert rules from API to domain model
	rules := make([]models.RuleRef, len(req.Rules))
	for i, rule := range req.Rules {
		//nolint:staticcheck // direct struct literal is clearer than conversion function
		rules[i] = models.RuleRef{
			RuleID:    rule.RuleID,
			Enabled:   rule.Enabled,
			Threshold: rule.Threshold,
		}
	}

	// Create rule set
	now := time.Now().UTC()
	ruleSet := &models.RuleSet{
		Name:        req.Name,
		Version:     req.Version,
		Description: req.Description,
		Enabled:     req.Enabled,
		Source:      source,
		Rules:       rules,
		Scope:       scope,
		IsDefault:   false, // Only ET Open can be default
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   subject.ID,
		UpdatedBy:   subject.ID,
	}

	// Check if this should be the default (ET Open)
	if source == models.RuleSetSourceETOpen {
		// Check if there's already a default
		defaultRuleSet, err := s.ruleSetStore.GetDefault(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to check for default rule set: %w", err)
		}

		if defaultRuleSet == nil {
			// This is the first ET Open rule set, make it default
			ruleSet.IsDefault = true
		}
	}

	// Persist rule set
	err = s.ruleSetStore.Create(ctx, ruleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule set: %w", err)
	}

	// Emit audit event for rule set creation (NH-RD-011)
	s.emitRuleSetAuditEvent(ctx, subject, "netshield.ruleset.create", *ruleSet)

	return ruleSet, nil
}

// Update updates an existing rule set.
// Implements NH-RD-003: Regelset-Management-APIs.
// Emits audit event per NH-RD-011.
func (s *RuleSetService) Update(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	id string,
	req models.UpdateRuleSetRequest,
) (*models.RuleSet, error) {
	logger.V(vplogging.LogLevelVerbose).Info("updating rule set", "id", id)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.update",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  id,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	// Get existing rule set
	ruleSet, err := s.ruleSetStore.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule set: %w", err)
	}

	if ruleSet == nil {
		return nil, ErrRuleSetNotFound
	}

	// Store old values for audit
	oldName := ruleSet.Name
	oldVersion := ruleSet.Version
	oldDescription := ruleSet.Description
	oldEnabled := ruleSet.Enabled
	oldScope := ruleSet.Scope
	oldRules := ruleSet.Rules

	// Create a copy to avoid modifying the input parameter (fixes race conditions in parallel tests)
	// This is critical: Production-Code must not mutate caller's data (ADR-0027/28)
	ruleSetCopy := *ruleSet

	// Update fields from request using helper method to reduce complexity
	if err := s.applyUpdateRequest(&ruleSetCopy, &req); err != nil {
		return nil, err
	}

	ruleSetCopy.UpdatedAt = time.Now().UTC()
	ruleSetCopy.UpdatedBy = subject.ID

	// Persist update
	err = s.ruleSetStore.Update(ctx, &ruleSetCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to update rule set: %w", err)
	}

	// Emit audit event for rule set update (NH-RD-011)
	// Check if scope changed by comparing individual fields
	scopeChanged := oldScope.Type != ruleSetCopy.Scope.Type ||
		oldScope.Namespace != ruleSetCopy.Scope.Namespace ||
		len(oldScope.DefconIDs) != len(ruleSetCopy.Scope.DefconIDs)

	if !scopeChanged && len(oldScope.DefconIDs) > 0 {
		// Check if DefconIDs are the same (order-independent)
		defconMap := make(map[string]bool, len(oldScope.DefconIDs))
		for _, id := range oldScope.DefconIDs {
			defconMap[id] = true
		}

		for _, id := range ruleSetCopy.Scope.DefconIDs {
			if !defconMap[id] {
				scopeChanged = true
				break
			}
		}
	}

	rulesChanged := len(oldRules) != len(ruleSetCopy.Rules)

	if !rulesChanged && len(oldRules) > 0 {
		// Check if rules are the same
		for i, oldRule := range oldRules {
			if i >= len(ruleSetCopy.Rules) {
				rulesChanged = true
				break
			}

			if oldRule.RuleID != ruleSetCopy.Rules[i].RuleID ||
				oldRule.Enabled != ruleSetCopy.Rules[i].Enabled ||
				oldRule.Threshold != ruleSetCopy.Rules[i].Threshold {
				rulesChanged = true
				break
			}
		}
	}

	meta := map[string]string{
		"previousName":        oldName,
		"newName":             ruleSetCopy.Name,
		"previousVersion":     oldVersion,
		"newVersion":          ruleSetCopy.Version,
		"previousDescription": oldDescription,
		"newDescription":      ruleSetCopy.Description,
		"previousEnabled":     fmt.Sprintf("%t", oldEnabled),
		"newEnabled":          fmt.Sprintf("%t", ruleSetCopy.Enabled),
		"scopeChanged":        fmt.Sprintf("%t", scopeChanged),
		"rulesChanged":        fmt.Sprintf("%t", rulesChanged),
	}
	s.emitRuleSetAuditEventWithMeta(ctx, subject, "netshield.ruleset.update", ruleSetCopy, meta)

	return &ruleSetCopy, nil
}

// Delete deletes a rule set by its ID.
// Implements NH-RD-003: Regelset-Management-APIs.
// Emits audit event per NH-RD-011.
func (s *RuleSetService) Delete(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	id string,
) error {
	logger.V(vplogging.LogLevelVerbose).Info("deleting rule set", "id", id)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.delete",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  id,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return authz.ErrAccessDenied
	}

	// Get existing rule set
	ruleSet, err := s.ruleSetStore.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get rule set: %w", err)
	}

	if ruleSet == nil {
		return ErrRuleSetNotFound
	}

	// Prevent deletion of default rule set
	if ruleSet.IsDefault {
		return ErrDefaultRuleSetCannotDelete
	}

	// Delete rule set
	err = s.ruleSetStore.Delete(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete rule set: %w", err)
	}

	// Emit audit event for rule set deletion (NH-RD-011)
	meta := map[string]string{
		"name":    ruleSet.Name,
		"version": ruleSet.Version,
		"source":  string(ruleSet.Source),
	}
	s.emitRuleSetAuditEventWithMeta(ctx, subject, "netshield.ruleset.delete", *ruleSet, meta)

	return nil
}

// Enable enables a rule set.
// Implements NH-RD-003: Regelset-Management-APIs.
// Emits audit event per NH-RD-011.
func (s *RuleSetService) Enable(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	id string,
) (*models.RuleSet, error) {
	logger.V(vplogging.LogLevelVerbose).Info("enabling rule set", "id", id)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.update",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  id,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	// Get existing rule set
	ruleSet, err := s.ruleSetStore.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule set: %w", err)
	}

	if ruleSet == nil {
		return nil, ErrRuleSetNotFound
	}

	// Check if already enabled
	if ruleSet.Enabled {
		return ruleSet, nil
	}

	ruleSet.Enabled = true
	ruleSet.UpdatedAt = time.Now().UTC()
	ruleSet.UpdatedBy = subject.ID

	// Persist update
	err = s.ruleSetStore.Update(ctx, ruleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to enable rule set: %w", err)
	}

	// Emit audit event for rule set enable (NH-RD-011)
	s.emitRuleSetAuditEvent(ctx, subject, "netshield.ruleset.enable", *ruleSet)

	return ruleSet, nil
}

// Disable disables a rule set.
// Implements NH-RD-003: Regelset-Management-APIs.
// Emits audit event per NH-RD-011.
func (s *RuleSetService) Disable(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	id string,
) (*models.RuleSet, error) {
	logger.V(vplogging.LogLevelVerbose).Info("disabling rule set", "id", id)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.update",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  id,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	// Get existing rule set
	ruleSet, err := s.ruleSetStore.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule set: %w", err)
	}

	if ruleSet == nil {
		return nil, ErrRuleSetNotFound
	}

	// Prevent disabling of default rule set
	if ruleSet.IsDefault {
		return nil, ErrDefaultRuleSetCannotDisable
	}

	// Check if already disabled
	if !ruleSet.Enabled {
		return ruleSet, nil
	}

	ruleSet.Enabled = false
	ruleSet.UpdatedAt = time.Now().UTC()
	ruleSet.UpdatedBy = subject.ID

	// Persist update
	err = s.ruleSetStore.Update(ctx, ruleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to disable rule set: %w", err)
	}

	// Emit audit event for rule set disable (NH-RD-011)
	s.emitRuleSetAuditEvent(ctx, subject, "netshield.ruleset.disable", *ruleSet)

	return ruleSet, nil
}

// GetDefault returns the default rule set (ET Open Baseline).
// Implements NH-RD-002: ET Open Baseline should be marked as default.
func (s *RuleSetService) GetDefault(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
) (*models.RuleSet, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting default rule set")

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.read",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  "default",
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	defaultRuleSet, err := s.ruleSetStore.GetDefault(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get default rule set: %w", err)
	}

	if defaultRuleSet == nil {
		return nil, ErrRuleSetNotFound
	}

	return defaultRuleSet, nil
}

// Render renders a rule set into Suricata-compatible format.
// Implements NH-RD-007: Regelset-Rendering.
func (s *RuleSetService) Render(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	id string,
) (string, error) {
	logger.V(vplogging.LogLevelVerbose).Info("rendering rule set", "id", id)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.read",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  id,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return "", fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return "", authz.ErrAccessDenied
	}

	// Get rule set
	ruleSet, err := s.ruleSetStore.GetByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to get rule set: %w", err)
	}

	if ruleSet == nil {
		return "", ErrRuleSetNotFound
	}

	// Get all rules referenced by the rule set
	ruleIDs := make([]string, 0, len(ruleSet.Rules))

	for _, ruleRef := range ruleSet.Rules {
		if ruleRef.Enabled {
			ruleIDs = append(ruleIDs, ruleRef.RuleID)
		}
	}

	rules, err := s.ruleStore.GetByRuleIDs(ctx, ruleIDs)
	if err != nil {
		return "", fmt.Errorf("failed to get rules: %w", err)
	}

	// Build Suricata-compatible output
	var sb strings.Builder

	// Add header comment
	sb.WriteString("# Rule Set: " + ruleSet.Name + "\n")
	sb.WriteString("# Version: " + ruleSet.Version + "\n")
	sb.WriteString("# Source: " + string(ruleSet.Source) + "\n")
	sb.WriteString("# Description: " + ruleSet.Description + "\n")
	sb.WriteString("# Generated: " + time.Now().UTC().Format(time.RFC3339) + "\n\n")

	// Add each rule
	for _, rule := range rules {
		if rule != nil && rule.Default {
			sb.WriteString(rule.Content + "\n")
		}
	}

	return sb.String(), nil
}

// GetRuleSetsByScope returns rule sets that apply to a specific scope.
// Used for Defcon/namespaced rule set resolution.
func (s *RuleSetService) GetRuleSetsByScope(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	scopeType models.ScopeType,
	defconID, namespace string,
) ([]*models.RuleSet, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting rule sets by scope",
		"scopeType", scopeType,
		"defconId", defconID,
		"namespace", namespace)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.ruleset.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "ruleset",
			ResourceRef:  string(scopeType) + ":" + defconID + ":" + namespace,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	ruleSets, err := s.ruleSetStore.GetByScope(ctx, scopeType, defconID, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule sets by scope: %w", err)
	}

	return ruleSets, nil
}

// applyUpdateRequest applies the update request to a rule set.
// This is a helper method to reduce cyclomatic complexity in Update().
func (s *RuleSetService) applyUpdateRequest(
	ruleSet *models.RuleSet,
	req *models.UpdateRuleSetRequest,
) error {
	// Update basic fields
	if req.Name != "" {
		ruleSet.Name = req.Name
	}

	if req.Version != "" {
		ruleSet.Version = req.Version
	}

	if req.Description != "" {
		ruleSet.Description = req.Description
	}

	if req.Enabled != nil && *req.Enabled != ruleSet.Enabled {
		// Only update if explicitly set in request
		ruleSet.Enabled = *req.Enabled
	}

	// Update source with validation
	if req.Source != "" {
		source := models.RuleSetSource(req.Source)
		if source != models.RuleSetSourceETOpen &&
			source != models.RuleSetSourceETPro &&
			source != models.RuleSetSourceCustom {
			return fmt.Errorf("invalid source %q: %w", req.Source, ErrInvalidSource)
		}

		ruleSet.Source = source
	}

	// Update scope if provided
	if req.Scope.Type != "" {
		ruleSet.Scope.Type = models.ScopeType(req.Scope.Type)
		ruleSet.Scope.DefconIDs = req.Scope.DefconIDs
		ruleSet.Scope.Namespace = req.Scope.Namespace
	}

	// Update rules if provided
	if len(req.Rules) > 0 {
		rules := make([]models.RuleRef, len(req.Rules))
		for i, rule := range req.Rules {
			//nolint:staticcheck // direct struct literal is clearer than conversion function
			rules[i] = models.RuleRef{
				RuleID:    rule.RuleID,
				Enabled:   rule.Enabled,
				Threshold: rule.Threshold,
			}
		}

		ruleSet.Rules = rules
	}

	return nil
}

// emitRuleSetAuditEvent emits an audit event for ruleset operations.
// Helper for NH-RD-011: Audit-Events fuer Regelset-Mutationen.
func (s *RuleSetService) emitRuleSetAuditEvent(
	ctx context.Context,
	subject *types.Subject,
	action string,
	ruleSet models.RuleSet,
) {
	correlationID, _ := correlation.FromContext(ctx)

	event := ironchronicle.Event{
		CorrelationID: correlationID,
		Actor: ironchronicle.Actor{
			Type: string(subject.Type),
			ID:   subject.ID,
		},
		Source: ironchronicle.Source{
			Kind: ironchronicle.SourceKindAPI,
		},
		Action: action,
		Subject: ironchronicle.Subject{
			Type: "netshield.ruleset",
			ID:   ruleSet.ID.Hex(),
		},
		Result: ironchronicle.ResultSuccess,
		Meta: map[string]string{
			"name":      ruleSet.Name,
			"version":   ruleSet.Version,
			"source":    string(ruleSet.Source),
			"enabled":   fmt.Sprintf("%t", ruleSet.Enabled),
			"isDefault": fmt.Sprintf("%t", ruleSet.IsDefault),
			"scopeType": string(ruleSet.Scope.Type),
			"ruleCount": fmt.Sprintf("%d", len(ruleSet.Rules)),
		},
	}

	ironchronicle.Emit(ctx, event)
}

// emitRuleSetAuditEventWithMeta emits an audit event with additional metadata.
// Helper for NH-RD-011: Audit-Events fuer Regelset-Mutationen.
func (s *RuleSetService) emitRuleSetAuditEventWithMeta(
	ctx context.Context,
	subject *types.Subject,
	action string,
	ruleSet models.RuleSet,
	meta map[string]string,
) {
	correlationID, _ := correlation.FromContext(ctx)

	// Merge base meta with additional meta
	mergedMeta := map[string]string{
		"name":      ruleSet.Name,
		"version":   ruleSet.Version,
		"source":    string(ruleSet.Source),
		"enabled":   fmt.Sprintf("%t", ruleSet.Enabled),
		"isDefault": fmt.Sprintf("%t", ruleSet.IsDefault),
		"scopeType": string(ruleSet.Scope.Type),
		"ruleCount": fmt.Sprintf("%d", len(ruleSet.Rules)),
	}

	// Add custom meta (custom meta takes precedence)
	for k, v := range meta {
		mergedMeta[k] = v
	}

	event := ironchronicle.Event{
		CorrelationID: correlationID,
		Actor: ironchronicle.Actor{
			Type: string(subject.Type),
			ID:   subject.ID,
		},
		Source: ironchronicle.Source{
			Kind: ironchronicle.SourceKindAPI,
		},
		Action: action,
		Subject: ironchronicle.Subject{
			Type: "netshield.ruleset",
			ID:   ruleSet.ID.Hex(),
		},
		Result: ironchronicle.ResultSuccess,
		Meta:   mergedMeta,
	}

	ironchronicle.Emit(ctx, event)
}
