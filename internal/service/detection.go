// Package service provides the business logic layer for NetShield.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/crossbc"
	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/vp-lib/authz"
	"vigilprotector.io/vp-lib/correlation"
	"vigilprotector.io/vp-lib/ironchronicle"
	vplogging "vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// Errors for the detection service.
var (
	// ErrDetectionNotFound is returned when a detection is not found.
	ErrDetectionNotFound = errors.New("detection not found")
	// ErrDetectionAlreadyExists is returned when a detection already exists.
	ErrDetectionAlreadyExists = errors.New("detection already exists")
	// ErrInvalidEventType is returned when an invalid event type is provided.
	ErrInvalidEventType = errors.New("invalid event type")
	// ErrNotDetectionEvent is returned when the event type is not a detection event.
	ErrNotDetectionEvent = errors.New("event type is not a detection event")
	// ErrDetectionAlreadyProcessed is returned when a detection is already processed.
	ErrDetectionAlreadyProcessed = errors.New("detection already processed")
)

// DetectionStorer defines the interface for detection persistence operations.
// Consumer-defined interface pattern: defined where consumed (service layer).
type DetectionStorer interface {
	// List returns a paginated list of detections with optional filtering.
	List(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetByID returns a single detection by its ID.
	GetByID(ctx context.Context, detectionID string) (*models.Detection, error)
	// GetByDetectionID returns a single detection by its detection ID.
	GetByDetectionID(ctx context.Context, detectionID string) (*models.Detection, error)
	// Create creates a new detection.
	Create(ctx context.Context, detection *models.Detection) error
	// Update updates an existing detection.
	Update(ctx context.Context, detection *models.Detection) error
	// Delete deletes a detection by its ID.
	Delete(ctx context.Context, id string) error
	// GetBySensorID returns detections for a specific sensor.
	GetBySensorID(ctx context.Context, sensorID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetByPicketID returns detections for a specific Picket.
	GetByPicketID(ctx context.Context, picketID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetByRuleSetID returns detections for a specific rule set.
	GetByRuleSetID(ctx context.Context, ruleSetID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetByRuleID returns detections for a specific rule.
	GetByRuleID(ctx context.Context, ruleID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetUnprocessed returns detections that have not been processed yet.
	GetUnprocessed(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
}

// DetectionServiceInterface defines the interface for detection service operations.
// This is the public interface that handlers consume.
// Consumer-defined interface pattern: defined where consumed (handler layer).
type DetectionServiceInterface interface {
	// List returns a paginated list of detections with optional filtering.
	List(ctx context.Context, logger logr.Logger, subject *types.Subject, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// Get returns a single detection by its ID.
	Get(ctx context.Context, logger logr.Logger, subject *types.Subject, detectionID string) (*models.Detection, error)
	// Create creates a new detection from SuricataGate.
	Create(ctx context.Context, logger logr.Logger, subject *types.Subject, detection *models.Detection) (*models.Detection, error)
	// ProcessDetection processes a detection and creates a finding if appropriate.
	// Implements NH-CC-001..004, NH-LM-007, NH-FD-001..004.
	ProcessDetection(ctx context.Context, logger logr.Logger, subject *types.Subject, detectionID string) (*models.Finding, error)
	// MarkAsProcessed marks a detection as processed.
	MarkAsProcessed(ctx context.Context, logger logr.Logger, subject *types.Subject, detectionID string) error
	// GetBySensorID returns detections for a specific sensor.
	GetBySensorID(ctx context.Context, logger logr.Logger, subject *types.Subject, sensorID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetByPicketID returns detections for a specific Picket.
	GetByPicketID(ctx context.Context, logger logr.Logger, subject *types.Subject, picketID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetByRuleSetID returns detections for a specific rule set.
	GetByRuleSetID(ctx context.Context, logger logr.Logger, subject *types.Subject, ruleSetID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetByRuleID returns detections for a specific rule.
	GetByRuleID(ctx context.Context, logger logr.Logger, subject *types.Subject, ruleID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	// GetUnprocessed returns detections that have not been processed yet.
	GetUnprocessed(ctx context.Context, logger logr.Logger, subject *types.Subject, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
}

// FlowSeekerClient defines the interface for FlowSeeker API operations.
// Used for context correlation (NH-CC-001..004, NH-LM-006).
type FlowSeekerClient interface {
	// GetFlowContext returns flow context for a given source/dest IP pair.
	GetFlowContext(ctx context.Context, srcIP, dstIP string, startTime, endTime time.Time) (*FlowContext, error)
}

// FlowContext represents flow context from FlowSeeker.
type FlowContext struct {
	// FlowID is the unique identifier for the flow.
	FlowID string
	// SourceIP is the source IP address.
	SourceIP string
	// DestIP is the destination IP address.
	DestIP string
	// Proto is the protocol.
	Proto string
	// SourcePort is the source port.
	SourcePort int
	// DestPort is the destination port.
	DestPort int
	// BytesSent is the number of bytes sent.
	BytesSent int64
	// BytesReceived is the number of bytes received.
	BytesReceived int64
	// StartTime is the start time of the flow.
	StartTime time.Time
	// EndTime is the end time of the flow.
	EndTime time.Time
	// AssetID is the asset ID for the source IP.
	AssetID string
	// DefconID is the Defcon ID for the source IP.
	DefconID string
	// Zone is the zone for the source IP.
	Zone string
	// Criticality is the criticality of the source asset.
	Criticality string
	// Enrichment is the cross-BC resolver outcome attached after
	// enrichWithCrossBCContext has run. nil means enrichment hasn't
	// executed yet (e.g. legacy paths in tests). Consumers that need
	// conflict provenance read it via flowCtx.Enrichment.Conflicts.
	// NH-CC-003 / VP-2235.
	Enrichment *crossbc.EnrichmentResult
}

// DetectionService implements business logic for detection operations.
type DetectionService struct {
	store        DetectionStorer
	findingStore FindingStorer
	flowSeeker   FlowSeekerClient
	logger       logr.Logger
}

// NewDetectionService creates a new DetectionService.
func NewDetectionService(
	store DetectionStorer,
	findingStore FindingStorer,
	flowSeeker FlowSeekerClient,
	logger logr.Logger,
) *DetectionService {
	return &DetectionService{
		store:        store,
		findingStore: findingStore,
		flowSeeker:   flowSeeker,
		logger:       logger,
	}
}

// Verify that DetectionService implements DetectionServiceInterface.
var _ DetectionServiceInterface = (*DetectionService)(nil)

// List returns a paginated list of detections with optional filtering.
func (s *DetectionService) List(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("listing detections",
		"filter", opts.Filter,
		"limit", opts.Limit,
		"offset", opts.Offset)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
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

	// Audit event for read operation (ADR-0041/0055)
	if s.shouldEmitDomainAudit(ctx, "netshield.detection.list") {
		s.emitDetectionAuditEvent(ctx, subject, "netshield.detection.list", models.Detection{})
	}

	response, err := s.store.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list detections from store: %w", err)
	}

	return response, nil
}

// Get returns a single detection by its ID.
func (s *DetectionService) Get(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	detectionID string,
) (*models.Detection, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detection by id", "detectionId", detectionID)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.read",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  detectionID,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	detection, err := s.store.GetByDetectionID(ctx, detectionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get detection from store: %w", err)
	}

	if detection == nil {
		return nil, ErrDetectionNotFound
	}

	// Audit event for read operation (ADR-0041/0055)
	if s.shouldEmitDomainAudit(ctx, "netshield.detection.read") {
		s.emitDetectionAuditEvent(ctx, subject, "netshield.detection.read", *detection)
	}

	return detection, nil
}

// Create creates a new detection from SuricataGate.
// Implements NH-SG-009: Only alert/anomaly events are routed to NetShield.
func (s *DetectionService) Create(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	detection *models.Detection,
) (*models.Detection, error) {
	logger.V(vplogging.LogLevelVerbose).Info("creating detection",
		"detectionId", detection.DetectionID,
		"sensorId", detection.SensorID,
		"picketId", detection.PicketID,
		"eventType", detection.EventType)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.create",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  detection.DetectionID,
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
	if detection.DetectionID == "" {
		return nil, fmt.Errorf("detectionId is required: %w", ErrDetectionAlreadyExists)
	}

	if detection.SensorID == "" && detection.PicketID == "" {
		return nil, fmt.Errorf("sensorId or picketId is required: %w", ErrDetectionAlreadyExists)
	}

	if detection.EventType == "" {
		return nil, fmt.Errorf("eventType is required: %w", ErrInvalidEventType)
	}

	// Validate event type is a detection event (NH-SG-009)
	if !detection.EventType.IsDetectionEvent() {
		return nil, fmt.Errorf("event type %q is not a detection event: %w", detection.EventType, ErrNotDetectionEvent)
	}

	// Create a copy to avoid modifying the input parameter (fixes race conditions in parallel tests)
	// This is critical: Production-Code must not mutate caller's data (ADR-0027/28)
	detectionCopy := *detection

	// Set timestamps
	now := time.Now().UTC()
	detectionCopy.CreatedAt = now
	detectionCopy.UpdatedAt = now

	// Check if detection already exists
	existing, err := s.store.GetByDetectionID(ctx, detectionCopy.DetectionID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing detection: %w", err)
	}

	if existing != nil {
		return nil, ErrDetectionAlreadyExists
	}

	// Persist detection
	err = s.store.Create(ctx, &detectionCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to create detection: %w", err)
	}

	// Emit audit event for detection creation
	s.emitDetectionAuditEvent(ctx, subject, "netshield.detection.create", detectionCopy)

	return &detectionCopy, nil
}

// ProcessDetection processes a detection and creates a finding if appropriate.
// Implements NH-CC-001..004: Context-Correlation-Input-Adapter.
// Implements NH-LM-006: Event-driven Enrichment-Pipeline.
// Implements NH-LM-007: Emission network.lateral_movement_suspected.
// Implements NH-FD-001..004: Core-Findings creation.
func (s *DetectionService) ProcessDetection(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	detectionID string,
) (*models.Finding, error) {
	logger.V(vplogging.LogLevelVerbose).Info("processing detection", "detectionId", detectionID)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.process",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  detectionID,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	// Get detection
	detection, err := s.store.GetByDetectionID(ctx, detectionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get detection: %w", err)
	}

	if detection == nil {
		return nil, ErrDetectionNotFound
	}

	// Skip if already processed
	// We'll use a simple check: if the detection has been updated after creation,
	// it might have been processed. In a real implementation, we'd have a processed flag.
	if detection.CreatedAt != detection.UpdatedAt {
		logger.V(vplogging.LogLevelDebug).Info("detection already processed", "detectionId", detectionID)
		return nil, ErrDetectionAlreadyProcessed
	}

	// Step 1: Correlate with context from FlowSeeker (NH-CC-001..004)
	// This enriches the detection with flow context
	ctxErr := s.correlateWithContext(ctx, logger, detection)
	if ctxErr != nil {
		logger.V(vplogging.LogLevelDebug).Info("failed to correlate detection with context",
			"detectionId", detectionID, "error", ctxErr)
	}

	// Step 2: Convert detection to finding (NH-LM-007, NH-FD-001..004)
	// For now, we'll use the CreateFindingFromDetection helper
	// In a real implementation, we'd have more sophisticated mapping
	finding := models.CreateFindingFromDetection(detection, detection.DefconID, detection.AssetID)

	// Step 3: Create the finding
	createdFinding, err := s.createFindingFromDetection(ctx, logger, subject, detection, finding)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding from detection: %w", err)
	}

	// Step 4: Mark detection as processed
	err = s.MarkAsProcessed(ctx, logger, subject, detectionID)
	if err != nil {
		logger.V(vplogging.LogLevelDebug).Info("failed to mark detection as processed",
			"detectionId", detectionID, "error", err)
	}

	// Emit audit event for detection processing
	meta := map[string]string{
		"findingId":   createdFinding.FindingID,
		"findingType": string(createdFinding.FindingType),
		"severity":    string(createdFinding.Severity),
		"assetId":     createdFinding.AssetID,
		"defconId":    createdFinding.DefconID,
	}
	s.emitDetectionAuditEventWithMeta(ctx, subject, "netshield.detection.process", *detection, meta)

	return createdFinding, nil
}

// createFindingFromDetection creates a finding from a detection.
func (s *DetectionService) createFindingFromDetection(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	detection *models.Detection,
	finding *models.Finding,
) (*models.Finding, error) {
	// If we have context from FlowSeeker, enrich the finding
	if detection.AssetID != "" {
		// Already enriched from context correlation
		finding.AssetID = detection.AssetID
	}

	if detection.DefconID != "" {
		finding.DefconID = detection.DefconID
	}

	// Set the source context
	finding.SourceContext = "netshield"

	// Create the finding
	err := s.findingStore.Create(ctx, finding)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding: %w", err)
	}

	return finding, nil
}

// correlateWithContext correlates a detection with flow context from FlowSeeker.
// Implements NH-CC-001..004: Context-Correlation-Input-Adapter.
func (s *DetectionService) correlateWithContext(
	ctx context.Context,
	logger logr.Logger,
	detection *models.Detection,
) error {
	logger.V(vplogging.LogLevelVerbose).Info("correlating detection with flow context",
		"detectionId", detection.DetectionID,
		"sourceIp", detection.SourceIP,
		"destIp", detection.DestIP)

	// Skip if FlowSeeker client is not configured
	if s.flowSeeker == nil {
		logger.V(vplogging.LogLevelDebug).Info("flowSeeker client not configured, skipping context correlation")
		return nil
	}

	// Skip if no IPs are available
	if detection.SourceIP == "" && detection.DestIP == "" {
		return nil
	}

	// Get flow context from FlowSeeker
	// Use a small time window around the detection timestamp
	windowStart := detection.Timestamp.Add(-5 * time.Minute)
	windowEnd := detection.Timestamp.Add(5 * time.Minute)

	flowCtx, err := s.flowSeeker.GetFlowContext(
		ctx,
		detection.SourceIP,
		detection.DestIP,
		windowStart,
		windowEnd,
	)
	if err != nil {
		return fmt.Errorf("failed to get flow context: %w", err)
	}

	if flowCtx == nil {
		return nil
	}

	// Create a copy to avoid modifying the input parameter (fixes race conditions in parallel tests)
	// This is critical: Production-Code must not mutate caller's data (ADR-0027/28)
	detectionCopy := *detection

	// Enrich detection copy with flow context
	if flowCtx.AssetID != "" {
		detectionCopy.AssetID = flowCtx.AssetID
	}

	if flowCtx.DefconID != "" {
		detectionCopy.DefconID = flowCtx.DefconID
	}

	// Update detection copy with enriched context
	detectionCopy.UpdatedAt = time.Now().UTC()

	err = s.store.Update(ctx, &detectionCopy)
	if err != nil {
		return fmt.Errorf("failed to update detection with context: %w", err)
	}

	logger.V(vplogging.LogLevelVerbose).Info("detection correlated with flow context",
		"detectionId", detectionCopy.DetectionID,
		"assetId", flowCtx.AssetID,
		"defconId", flowCtx.DefconID,
		"zone", flowCtx.Zone)

	return nil
}

// MarkAsProcessed marks a detection as processed.
func (s *DetectionService) MarkAsProcessed(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	detectionID string,
) error {
	logger.V(vplogging.LogLevelVerbose).Info("marking detection as processed", "detectionId", detectionID)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.update",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  detectionID,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return authz.ErrAccessDenied
	}

	// Get detection
	detection, err := s.store.GetByDetectionID(ctx, detectionID)
	if err != nil {
		return fmt.Errorf("failed to get detection: %w", err)
	}

	if detection == nil {
		return ErrDetectionNotFound
	}

	// Create a copy to avoid modifying the input parameter (fixes race conditions in parallel tests)
	// This is critical: Production-Code must not mutate caller's data (ADR-0027/28)
	detectionCopy := *detection

	// Update timestamp to mark as processed
	detectionCopy.UpdatedAt = time.Now().UTC()

	// Persist update
	err = s.store.Update(ctx, &detectionCopy)
	if err != nil {
		return fmt.Errorf("failed to mark detection as processed: %w", err)
	}

	// Emit audit event for marking as processed
	s.emitDetectionAuditEvent(ctx, subject, "netshield.detection.processed", detectionCopy)

	return nil
}

// GetBySensor returns detections for a specific sensor.
func (s *DetectionService) GetBySensor(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	sensorID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detections by sensorId", "sensorId", sensorID)

	response, err := s.store.GetBySensorID(ctx, sensorID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get detections by sensor: %w", err)
	}

	return response, nil
}

// GetByPicket returns detections for a specific Picket.
func (s *DetectionService) GetByPicket(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	picketID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detections by picketId", "picketId", picketID)

	response, err := s.store.GetByPicketID(ctx, picketID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get detections by picket: %w", err)
	}

	return response, nil
}

// GetByRuleSet returns detections for a specific rule set.
func (s *DetectionService) GetByRuleSet(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	ruleSetID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detections by ruleSetId", "ruleSetId", ruleSetID)

	response, err := s.store.GetByRuleSetID(ctx, ruleSetID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get detections by ruleSet: %w", err)
	}

	return response, nil
}

// GetUnprocessed returns detections that have not been processed yet.
// Implements DetectionServiceInterface.
func (s *DetectionService) GetUnprocessed(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting unprocessed detections")

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
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

	response, err := s.store.GetUnprocessed(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get unprocessed detections: %w", err)
	}

	return response, nil
}

// ProcessUnprocessed processes all unprocessed detections.
// Used for batch processing of detections.
func (s *DetectionService) ProcessUnprocessed(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	batchSize int,
) (int, error) {
	logger.V(vplogging.LogLevelVerbose).Info("processing unprocessed detections", "batchSize", batchSize)

	// Get unprocessed detections
	opts := models.ListDetectionsOptions{
		Filter:  models.DetectionFilter{},
		Limit:   batchSize,
		Offset:  0,
		SortBy:  "timestamp",
		SortAsc: true,
	}

	response, err := s.store.GetUnprocessed(ctx, opts)
	if err != nil {
		return 0, fmt.Errorf("failed to get unprocessed detections: %w", err)
	}

	processedCount := 0

	for _, detection := range response.Items {
		_, err := s.ProcessDetection(ctx, logger, subject, detection.DetectionID)
		if err != nil {
			logger.V(vplogging.LogLevelDebug).Info("failed to process detection",
				"detectionId", detection.DetectionID, "error", err)

			// Continue with next detection
			continue
		}

		processedCount++
	}

	logger.V(vplogging.LogLevelVerbose).Info("processed unprocessed detections", "count", processedCount)

	return processedCount, nil
}

// shouldEmitDomainAudit determines if domain audit events should be emitted.
// ADR-0041/0055: Services emit domain events; vp-lib handles AuthN/AuthZ auditing.
// For state-changing operations (create, update, delete, process), always emit.
// For read/list operations, emit when the active customer audit policy enables domain access auditing.
func (s *DetectionService) shouldEmitDomainAudit(ctx context.Context, action string) bool {
	// Extract correlation ID from context
	_, ok := correlation.FromContext(ctx)
	if !ok {
		return false
	}

	// For state-changing operations, always emit
	switch action {
	case "netshield.detection.create",
		"netshield.detection.update",
		"netshield.detection.delete",
		"netshield.detection.process",
		"netshield.detection.processed",
		"netshield.detection.mark-processed":
		return true
	}

	// For read/list operations, check if domain access auditing is enabled
	// This is a placeholder - in production, this would check the active customer audit policy.
	// For now, we emit read audits for development/traceability.
	return true
}

// emitDetectionAuditEvent emits an audit event for detection operations.
// ADR-0041/0055: Services emit domain events; vp-lib handles AuthN/AuthZ auditing.
func (s *DetectionService) emitDetectionAuditEvent(
	ctx context.Context,
	subject *types.Subject,
	action string,
	detection models.Detection,
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
			Type: "netshield.detection",
			ID:   detection.DetectionID,
		},
		Result: ironchronicle.ResultSuccess,
		Meta: map[string]string{
			"sensorId":   detection.SensorID,
			"picketId":   detection.PicketID,
			"ruleSetId":  detection.RuleSetID,
			"ruleId":     detection.RuleID,
			"eventType":  string(detection.EventType),
			"signature":  detection.Signature,
			"category":   detection.Category,
			"severity":   string(detection.Severity),
			"confidence": string(detection.Confidence),
			"sourceIp":   detection.SourceIP,
			"destIp":     detection.DestIP,
			"assetId":    detection.AssetID,
			"defconId":   detection.DefconID,
		},
	}

	ironchronicle.Emit(ctx, event)
}

// emitDetectionAuditEventWithMeta emits an audit event with additional metadata.
// Helper for audit event emission.
func (s *DetectionService) emitDetectionAuditEventWithMeta(
	ctx context.Context,
	subject *types.Subject,
	action string,
	detection models.Detection,
	meta map[string]string,
) {
	correlationID, _ := correlation.FromContext(ctx)

	// Merge base meta with additional meta
	mergedMeta := map[string]string{
		"sensorId":   detection.SensorID,
		"picketId":   detection.PicketID,
		"ruleSetId":  detection.RuleSetID,
		"ruleId":     detection.RuleID,
		"eventType":  string(detection.EventType),
		"signature":  detection.Signature,
		"category":   detection.Category,
		"severity":   string(detection.Severity),
		"confidence": string(detection.Confidence),
		"sourceIp":   detection.SourceIP,
		"destIp":     detection.DestIP,
		"assetId":    detection.AssetID,
		"defconId":   detection.DefconID,
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
			Type: "netshield.detection",
			ID:   detection.DetectionID,
		},
		Result: ironchronicle.ResultSuccess,
		Meta:   mergedMeta,
	}

	ironchronicle.Emit(ctx, event)
}

// GetBySensorID returns detections for a specific sensor.
// Implements DetectionServiceInterface.
func (s *DetectionService) GetBySensorID(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	sensorID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detections by sensorId", "sensorId", sensorID)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  sensorID,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	response, err := s.store.GetBySensorID(ctx, sensorID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get detections by sensor: %w", err)
	}

	return response, nil
}

// GetByPicketID returns detections for a specific Picket.
// Implements DetectionServiceInterface.
func (s *DetectionService) GetByPicketID(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	picketID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detections by picketId", "picketId", picketID)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  picketID,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	response, err := s.store.GetByPicketID(ctx, picketID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get detections by picket: %w", err)
	}

	return response, nil
}

// GetByRuleSetID returns detections for a specific rule set.
// Implements DetectionServiceInterface.
func (s *DetectionService) GetByRuleSetID(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	ruleSetID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detections by ruleSetId", "ruleSetId", ruleSetID)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  ruleSetID,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	response, err := s.store.GetByRuleSetID(ctx, ruleSetID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get detections by ruleSet: %w", err)
	}

	return response, nil
}

// GetByRuleID returns detections for a specific rule.
// Implements DetectionServiceInterface.
func (s *DetectionService) GetByRuleID(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	ruleID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting detections by ruleId", "ruleId", ruleID)

	// AuthZ check before store access (ADR-0027/28, microservice-standard.md)
	input := authz.NewInput(
		subject,
		"netshield.detection.list",
		types.Scope{
			BCRef:        "stratoward",
			ResourceKind: "detection",
			ResourceRef:  ruleID,
		},
	)

	decision, err := authz.Authorize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !decision.Allow {
		return nil, authz.ErrAccessDenied
	}

	response, err := s.store.GetByRuleID(ctx, ruleID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get detections by rule: %w", err)
	}

	return response, nil
}
