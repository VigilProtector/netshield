// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/vp-lib/ironchronicle"
	vplogging "vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// Errors for the finding service.
var (
	// ErrFindingNotFound is returned when a finding is not found.
	ErrFindingNotFound = errors.New("finding not found")
	// ErrFindingAlreadyExists is returned when a finding already exists.
	ErrFindingAlreadyExists = errors.New("finding already exists")
	// ErrInvalidLifecycleTransition is returned when an invalid lifecycle transition is attempted.
	ErrInvalidLifecycleTransition = errors.New("invalid lifecycle transition")
	// ErrInvalidVerificationStatus is returned when an invalid verification status is provided.
	ErrInvalidVerificationStatus = errors.New("invalid verification status")
	// ErrInvalidFreshnessStatus is returned when an invalid freshness status is provided.
	ErrInvalidFreshnessStatus = errors.New("invalid freshness status")
	// ErrInvalidFindingType is returned when an invalid finding type is provided.
	ErrInvalidFindingType = errors.New("invalid finding type")
	// ErrInvalidSeverity is returned when an invalid severity is provided.
	ErrInvalidSeverity = errors.New("invalid severity")
)

// FindingStorer defines the interface for finding persistence operations.
// Consumer-defined interface pattern: defined where consumed (service layer).
type FindingStorer interface {
	// List returns a paginated list of findings with optional filtering.
	List(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// GetByID returns a single finding by its ID.
	GetByID(ctx context.Context, findingID string) (*models.Finding, error)
	// GetByFindingID returns a single finding by its finding ID.
	GetByFindingID(ctx context.Context, findingID string) (*models.Finding, error)
	// Create creates a new finding.
	Create(ctx context.Context, finding *models.Finding) error
	// Update updates an existing finding.
	Update(ctx context.Context, finding *models.Finding) error
	// Delete deletes a finding by its ID.
	Delete(ctx context.Context, id string) error
	// GetByAssetID returns findings for a specific asset.
	GetByAssetID(ctx context.Context, assetID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// GetByDefconID returns findings for a specific Defcon.
	GetByDefconID(ctx context.Context, defconID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// GetByFindingType returns findings of a specific type.
	GetByFindingType(ctx context.Context, findingType models.FindingType, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// GetStale returns findings that are stale.
	GetStale(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
}

// FindingServiceInterface defines the interface for finding service operations.
// This is the public interface that handlers consume.
// Consumer-defined interface pattern: defined where consumed (handler layer).
type FindingServiceInterface interface {
	// List returns a paginated list of findings with optional filtering.
	List(ctx context.Context, logger logr.Logger, subject *types.Subject, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// Get returns a single finding by its ID.
	Get(ctx context.Context, logger logr.Logger, subject *types.Subject, findingID string) (*models.Finding, error)
	// Create creates a new finding.
	Create(ctx context.Context, logger logr.Logger, subject *types.Subject, finding *models.Finding) (*models.Finding, error)
	// UpdateLifecycle updates the lifecycle status of a finding.
	UpdateLifecycle(ctx context.Context, logger logr.Logger, subject *types.Subject, findingID string, req models.UpdateFindingLifecycleRequest) (*models.Finding, error)
	// UpdateVerification updates the verification status of a finding.
	UpdateVerification(ctx context.Context, logger logr.Logger, subject *types.Subject, findingID string, req models.UpdateFindingVerificationRequest) (*models.Finding, error)
	// MarkStale marks findings as stale based on freshness thresholds.
	MarkStale(ctx context.Context, logger logr.Logger, subject *types.Subject, staleAfter time.Duration) (int, error)
	// GetByAsset returns findings for a specific asset.
	GetByAsset(ctx context.Context, logger logr.Logger, subject *types.Subject, assetID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// GetByDefcon returns findings for a specific Defcon.
	GetByDefcon(ctx context.Context, logger logr.Logger, subject *types.Subject, defconID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// GetByType returns findings of a specific type.
	GetByType(ctx context.Context, logger logr.Logger, subject *types.Subject, findingType models.FindingType, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	// GetStale returns findings that are stale.
	GetStale(ctx context.Context, logger logr.Logger, subject *types.Subject, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
}

// FindingService implements business logic for finding operations.
type FindingService struct {
	store  FindingStorer
	logger logr.Logger
}

// NewFindingService creates a new FindingService.
func NewFindingService(
	store FindingStorer,
	logger logr.Logger,
) *FindingService {
	return &FindingService{
		store:  store,
		logger: logger,
	}
}

// Verify that FindingService implements FindingServiceInterface.
var _ FindingServiceInterface = (*FindingService)(nil)

// List returns a paginated list of findings with optional filtering.
// Implements VL-FC-001: Finding listing with filtering.
func (s *FindingService) List(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("listing findings",
		"filter", opts.Filter,
		"limit", opts.Limit,
		"offset", opts.Offset)

	response, err := s.store.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings from store: %w", err)
	}

	return response, nil
}

// Get returns a single finding by its ID.
// Implements VL-FC-001: Get finding by ID.
func (s *FindingService) Get(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	findingID string,
) (*models.Finding, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting finding by id", "findingId", findingID)

	finding, err := s.store.GetByFindingID(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding from store: %w", err)
	}

	if finding == nil {
		return nil, ErrFindingNotFound
	}

	return finding, nil
}

// Create creates a new finding.
// Implements NH-FD-*: Core-Findings creation.
// Emits audit event for finding creation.
func (s *FindingService) Create(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	finding *models.Finding,
) (*models.Finding, error) {
	logger.V(vplogging.LogLevelVerbose).Info("creating finding",
		"findingId", finding.FindingID,
		"findingType", finding.FindingType,
		"severity", finding.Severity)

	// Validate required fields
	if finding.FindingID == "" {
		return nil, fmt.Errorf("findingId is required: %w", ErrFindingAlreadyExists)
	}

	if finding.FindingType == "" {
		return nil, fmt.Errorf("findingType is required: %w", ErrInvalidFindingType)
	}

	if finding.Severity == "" {
		return nil, fmt.Errorf("severity is required: %w", ErrInvalidSeverity)
	}

	if finding.Title == "" {
		return nil, fmt.Errorf("title is required: %w", ErrInvalidFindingType)
	}

	// Validate finding type
	if !s.IsValidFindingType(finding.FindingType) {
		return nil, fmt.Errorf("invalid finding type %q: %w", finding.FindingType, ErrInvalidFindingType)
	}

	// Validate severity
	if !s.IsValidSeverity(finding.Severity) {
		return nil, fmt.Errorf("invalid severity %q: %w", finding.Severity, ErrInvalidSeverity)
	}

	// Validate lifecycle
	if finding.Lifecycle.Status == "" {
		finding.Lifecycle.Status = models.FindingLifecycleStatusOpen
	}

	if !s.IsValidLifecycleStatus(finding.Lifecycle.Status) {
		return nil, fmt.Errorf("invalid lifecycle status %q: %w", finding.Lifecycle.Status, ErrInvalidLifecycleTransition)
	}

	// Validate verification
	if finding.Verification.Status == "" {
		finding.Verification.Status = models.FindingVerificationStatusUnverified
	}

	if !s.IsValidVerificationStatus(finding.Verification.Status) {
		return nil, fmt.Errorf("invalid verification status %q: %w", finding.Verification.Status, ErrInvalidVerificationStatus)
	}

	// Validate freshness
	if finding.Freshness.Status == "" {
		finding.Freshness.Status = models.FindingFreshnessStatusFresh
	}

	if !s.IsValidFreshnessStatus(finding.Freshness.Status) {
		return nil, fmt.Errorf("invalid freshness status %q: %w", finding.Freshness.Status, ErrInvalidFreshnessStatus)
	}

	// Set timestamps
	now := time.Now().UTC()
	finding.CreatedAt = now
	finding.UpdatedAt = now
	finding.SchemaVersion = models.FindingContractVersion

	// Set default window if not provided
	if finding.Window == nil && finding.OccurredAt.IsZero() {
		finding.OccurredAt = now
	}

	// Check if finding already exists
	existing, err := s.store.GetByFindingID(ctx, finding.FindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing finding: %w", err)
	}

	if existing != nil {
		return nil, ErrFindingAlreadyExists
	}

	// Persist finding
	err = s.store.Create(ctx, finding)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding: %w", err)
	}

	// Emit audit event for finding creation
	s.emitFindingAuditEvent(ctx, subject, "netshield.finding.create", *finding)

	return finding, nil
}

// UpdateLifecycle updates the lifecycle status of a finding.
// Implements VL-FC-001: Basis-Lifecycle open -> resolved -> closed.
// Emits audit event for lifecycle transition.
func (s *FindingService) UpdateLifecycle(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	findingID string,
	req models.UpdateFindingLifecycleRequest,
) (*models.Finding, error) {
	logger.V(vplogging.LogLevelVerbose).Info("updating finding lifecycle",
		"findingId", findingID,
		"status", req.Status)

	// Validate new status
	if !s.IsValidLifecycleStatus(req.Status) {
		return nil, fmt.Errorf("invalid lifecycle status %q: %w", req.Status, ErrInvalidLifecycleTransition)
	}

	// Get existing finding
	finding, err := s.store.GetByFindingID(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}

	if finding == nil {
		return nil, ErrFindingNotFound
	}

	// Validate transition
	if !s.IsValidLifecycleTransition(finding.Lifecycle.Status, req.Status) {
		return nil, fmt.Errorf("invalid transition from %q to %q: %w", finding.Lifecycle.Status, req.Status, ErrInvalidLifecycleTransition)
	}

	// Store old status for audit
	oldStatus := finding.Lifecycle.Status

	// Update lifecycle
	finding.Lifecycle.Status = req.Status
	finding.Lifecycle.TransitionedAt = pointerToTime(time.Now().UTC())
	finding.Lifecycle.TransitionedBy = req.TransitionedBy

	if req.Reason != "" {
		finding.Lifecycle.Reason = req.Reason
	}

	finding.UpdatedAt = time.Now().UTC()

	// Persist update
	err = s.store.Update(ctx, finding)
	if err != nil {
		return nil, fmt.Errorf("failed to update finding lifecycle: %w", err)
	}

	// Emit audit event for lifecycle transition
	meta := map[string]string{
		"previousStatus": string(oldStatus),
		"newStatus":      string(req.Status),
		"reason":         req.Reason,
		"transitionedBy": req.TransitionedBy,
	}
	s.emitFindingAuditEventWithMeta(ctx, subject, "netshield.finding.lifecycle.update", *finding, meta)

	return finding, nil
}

// UpdateVerification updates the verification status of a finding.
// Implements VL-FC-001: Verification dimension (unverified -> verified -> false_positive).
// Emits audit event for verification update.
func (s *FindingService) UpdateVerification(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	findingID string,
	req models.UpdateFindingVerificationRequest,
) (*models.Finding, error) {
	logger.V(vplogging.LogLevelVerbose).Info("updating finding verification",
		"findingId", findingID,
		"status", req.Status)

	// Validate new status
	if !s.IsValidVerificationStatus(req.Status) {
		return nil, fmt.Errorf("invalid verification status %q: %w", req.Status, ErrInvalidVerificationStatus)
	}

	// Get existing finding
	finding, err := s.store.GetByFindingID(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}

	if finding == nil {
		return nil, ErrFindingNotFound
	}

	// Store old status for audit
	oldStatus := finding.Verification.Status

	// Update verification
	finding.Verification.Status = req.Status
	finding.Verification.VerifiedAt = pointerToTime(time.Now().UTC())
	finding.Verification.VerifiedBy = req.VerifiedBy
	finding.Verification.Method = req.Method
	finding.Verification.Notes = req.Notes
	finding.UpdatedAt = time.Now().UTC()

	// Persist update
	err = s.store.Update(ctx, finding)
	if err != nil {
		return nil, fmt.Errorf("failed to update finding verification: %w", err)
	}

	// Emit audit event for verification update
	meta := map[string]string{
		"previousStatus": string(oldStatus),
		"newStatus":      string(req.Status),
		"method":         req.Method,
		"notes":          req.Notes,
		"verifiedBy":     req.VerifiedBy,
	}
	s.emitFindingAuditEventWithMeta(ctx, subject, "netshield.finding.verification.update", *finding, meta)

	return finding, nil
}

// MarkStale marks findings as stale based on freshness thresholds.
// Implements VL-FC-001: Freshness dimension.
// Emits audit events for stale markings.
func (s *FindingService) MarkStale(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	staleAfter time.Duration,
) (int, error) {
	logger.V(vplogging.LogLevelVerbose).Info("marking stale findings", "staleAfter", staleAfter)

	// Get all open findings
	opts := models.ListFindingsOptions{
		Filter: models.FindingFilter{
			Lifecycle: string(models.FindingLifecycleStatusOpen),
		},
		Limit:  0, // No limit
		Offset: 0,
	}

	response, err := s.store.List(ctx, opts)
	if err != nil {
		return 0, fmt.Errorf("failed to list findings: %w", err)
	}

	now := time.Now().UTC()
	staleCount := 0

	for _, finding := range response.Items {
		// Skip if already stale
		if finding.Freshness.Status == models.FindingFreshnessStatusStale {
			continue
		}

		// Check if finding is stale based on OccurredAt
		if now.Sub(finding.OccurredAt) > staleAfter {
			oldStatus := finding.Freshness.Status
			finding.Freshness.Status = models.FindingFreshnessStatusStale
			finding.Freshness.LastChecked = pointerToTime(now)
			finding.UpdatedAt = now

			err := s.store.Update(ctx, finding)
			if err != nil {
				logger.V(vplogging.LogLevelDebug).Info("failed to mark finding as stale",
					"findingId", finding.FindingID, "error", err)
				continue
			}

			// Emit audit event for stale marking
			meta := map[string]string{
				"previousStatus": string(oldStatus),
				"newStatus":      string(models.FindingFreshnessStatusStale),
				"reason":         "exceeded stale threshold",
			}
			s.emitFindingAuditEventWithMeta(ctx, subject, "netshield.finding.stale", *finding, meta)

			staleCount++
		}
	}

	logger.V(vplogging.LogLevelVerbose).Info("marked findings as stale", "count", staleCount)

	return staleCount, nil
}

// GetByAsset returns findings for a specific asset.
func (s *FindingService) GetByAsset(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	assetID string,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting findings by assetId", "assetId", assetID)

	response, err := s.store.GetByAssetID(ctx, assetID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings by asset: %w", err)
	}

	return response, nil
}

// GetByDefcon returns findings for a specific Defcon.
func (s *FindingService) GetByDefcon(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	defconID string,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting findings by defconId", "defconId", defconID)

	response, err := s.store.GetByDefconID(ctx, defconID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings by defcon: %w", err)
	}

	return response, nil
}

// GetByType returns findings of a specific type.
func (s *FindingService) GetByType(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	findingType models.FindingType,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting findings by type", "findingType", findingType)

	// Validate finding type
	if !s.IsValidFindingType(findingType) {
		return nil, fmt.Errorf("invalid finding type %q: %w", findingType, ErrInvalidFindingType)
	}

	response, err := s.store.GetByFindingType(ctx, findingType, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings by type: %w", err)
	}

	return response, nil
}

// GetStale returns findings that are stale.
func (s *FindingService) GetStale(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting stale findings")

	response, err := s.store.GetStale(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get stale findings: %w", err)
	}

	return response, nil
}

// IsValidFindingType checks if a finding type is valid.
func (s *FindingService) IsValidFindingType(findingType models.FindingType) bool {
	switch findingType {
	case models.FindingTypeKnownAttackPatternDetected,
		models.FindingTypeLateralMovementSuspected,
		models.FindingTypeNetworkPolicyViolationDetected,
		models.FindingTypeConfigDriftUnauthorized,
		models.FindingTypeConfigBaselineMissing:
		return true
	default:
		return false
	}
}

// IsValidSeverity checks if a severity is valid.
func (s *FindingService) IsValidSeverity(severity models.FindingSeverity) bool {
	switch severity {
	case models.FindingSeverityCritical,
		models.FindingSeverityHigh,
		models.FindingSeverityMedium,
		models.FindingSeverityLow,
		models.FindingSeverityInfo:
		return true
	default:
		return false
	}
}

// IsValidLifecycleStatus checks if a lifecycle status is valid.
func (s *FindingService) IsValidLifecycleStatus(status models.FindingLifecycleStatus) bool {
	switch status {
	case models.FindingLifecycleStatusOpen,
		models.FindingLifecycleStatusResolved,
		models.FindingLifecycleStatusClosed:
		return true
	default:
		return false
	}
}

// IsValidLifecycleTransition checks if a lifecycle transition is valid.
// Valid transitions per VL-FC-001:
//
//	open -> resolved
//	open -> closed
//	resolved -> closed
func (s *FindingService) IsValidLifecycleTransition(
	from, to models.FindingLifecycleStatus,
) bool {
	// Can always transition to same state (idempotent)
	if from == to {
		return true
	}

	// Valid transitions
	switch from {
	case models.FindingLifecycleStatusOpen:
		return to == models.FindingLifecycleStatusResolved || to == models.FindingLifecycleStatusClosed
	case models.FindingLifecycleStatusResolved:
		return to == models.FindingLifecycleStatusClosed
	case models.FindingLifecycleStatusClosed:
		// Cannot transition from closed
		return false
	default:
		return false
	}
}

// IsValidVerificationStatus checks if a verification status is valid.
func (s *FindingService) IsValidVerificationStatus(status models.FindingVerificationStatus) bool {
	switch status {
	case models.FindingVerificationStatusUnverified,
		models.FindingVerificationStatusVerified,
		models.FindingVerificationStatusFalsePositive:
		return true
	default:
		return false
	}
}

// IsValidFreshnessStatus checks if a freshness status is valid.
func (s *FindingService) IsValidFreshnessStatus(status models.FindingFreshnessStatus) bool {
	switch status {
	case models.FindingFreshnessStatusFresh,
		models.FindingFreshnessStatusStale:
		return true
	default:
		return false
	}
}

// emitFindingAuditEvent emits an audit event for finding operations.
// Helper for audit event emission.
func (s *FindingService) emitFindingAuditEvent(
	ctx context.Context,
	subject *types.Subject,
	action string,
	finding models.Finding,
) {
	event := ironchronicle.Event{
		Actor: ironchronicle.Actor{
			Type: string(subject.Type),
			ID:   subject.ID,
		},
		Source: ironchronicle.Source{
			Kind: ironchronicle.SourceKindAPI,
		},
		Action: action,
		Subject: ironchronicle.Subject{
			Type: "netshield.finding",
			ID:   finding.FindingID,
		},
		Result: ironchronicle.ResultSuccess,
		Meta: map[string]string{
			"findingType":   string(finding.FindingType),
			"severity":      string(finding.Severity),
			"title":         finding.Title,
			"lifecycle":     string(finding.Lifecycle.Status),
			"verification":  string(finding.Verification.Status),
			"freshness":     string(finding.Freshness.Status),
			"assetId":       finding.AssetID,
			"defconId":      finding.DefconID,
			"schemaVersion": finding.SchemaVersion,
		},
	}

	ironchronicle.Emit(ctx, event)
}

// emitFindingAuditEventWithMeta emits an audit event with additional metadata.
// Helper for audit event emission.
func (s *FindingService) emitFindingAuditEventWithMeta(
	ctx context.Context,
	subject *types.Subject,
	action string,
	finding models.Finding,
	meta map[string]string,
) {
	// Merge base meta with additional meta
	mergedMeta := map[string]string{
		"findingType":   string(finding.FindingType),
		"severity":      string(finding.Severity),
		"title":         finding.Title,
		"lifecycle":     string(finding.Lifecycle.Status),
		"verification":  string(finding.Verification.Status),
		"freshness":     string(finding.Freshness.Status),
		"assetId":       finding.AssetID,
		"defconId":      finding.DefconID,
		"schemaVersion": finding.SchemaVersion,
	}

	// Add custom meta (custom meta takes precedence)
	for k, v := range meta {
		mergedMeta[k] = v
	}

	event := ironchronicle.Event{
		Actor: ironchronicle.Actor{
			Type: string(subject.Type),
			ID:   subject.ID,
		},
		Source: ironchronicle.Source{
			Kind: ironchronicle.SourceKindAPI,
		},
		Action: action,
		Subject: ironchronicle.Subject{
			Type: "netshield.finding",
			ID:   finding.FindingID,
		},
		Result: ironchronicle.ResultSuccess,
		Meta:   mergedMeta,
	}

	ironchronicle.Emit(ctx, event)
}

// pointerToTime is a helper to convert time.Time to *time.Time.
func pointerToTime(t time.Time) *time.Time {
	return &t
}
