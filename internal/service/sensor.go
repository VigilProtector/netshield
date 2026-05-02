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

// Errors for the sensor service.
var (
	// ErrSensorNotFound is returned when a sensor is not found.
	ErrSensorNotFound = errors.New("sensor not found")
	// ErrSensorAlreadyExists is returned when a sensor already exists.
	ErrSensorAlreadyExists = errors.New("sensor already exists")
	// ErrInvalidStatus is returned when an invalid status is provided.
	ErrInvalidStatus = errors.New("invalid sensor status")
	// ErrInvalidHealth is returned when an invalid health is provided.
	ErrInvalidHealth = errors.New("invalid sensor health")
)

// SensorServiceInterface defines the interface for sensor service operations.
// This is the public interface that handlers consume.
// Consumer-defined interface pattern: defined where consumed (handler layer).
type SensorServiceInterface interface {
	// List returns a paginated list of sensors with optional filtering and Defcon enrichment.
	List(ctx context.Context, logger logr.Logger, subject *types.Subject, opts ListSensorsOptions) (*ListSensorsResult, error)
	// Get returns a single sensor by its Picket ID with Defcon enrichment.
	Get(ctx context.Context, logger logr.Logger, subject *types.Subject, picketID string) (*models.Sensor, error)
	// Register registers a new Picket sensor.
	Register(ctx context.Context, logger logr.Logger, subject *types.Subject, sensor *models.Sensor) (*models.Sensor, error)
	// UpdateStatus updates the operational status and health of a sensor.
	UpdateStatus(ctx context.Context, logger logr.Logger, subject *types.Subject, picketID string, status models.SensorStatus, health models.SensorHealth) (*models.Sensor, error)
	// UpdateLastSeen updates the last seen timestamp for a sensor.
	UpdateLastSeen(ctx context.Context, logger logr.Logger, subject *types.Subject, picketID string) (*models.Sensor, error)
	// UpdateRuleVersion updates the rule version for a sensor.
	UpdateRuleVersion(ctx context.Context, logger logr.Logger, subject *types.Subject, picketID string, version string) (*models.Sensor, error)
}

// SensorStorer defines the interface for sensor persistence operations.
// Consumer-defined interface pattern: defined where consumed (service layer).
type SensorStorer interface {
	// List returns a paginated list of sensors with optional filtering.
	List(ctx context.Context, opts models.ListSensorsOptions) (*models.SensorListResponse, error)
	// GetByPicketID returns a single sensor by its Picket ID.
	GetByPicketID(ctx context.Context, picketID string) (*models.Sensor, error)
	// Create creates a new sensor.
	Create(ctx context.Context, sensor *models.Sensor) error
	// Update updates an existing sensor.
	Update(ctx context.Context, sensor *models.Sensor) error
	// GetByDefconID returns sensors for a specific Defcon.
	GetByDefconID(ctx context.Context, defconID string) ([]*models.Sensor, error)
}

// Verify that SensorService implements SensorServiceInterface.
var _ SensorServiceInterface = (*SensorService)(nil)

// VigilNetClient defines the interface for VigilNet API operations.
// Used for Defcon name enrichment.
type VigilNetClient interface {
	// GetDefconName returns the name for a given Defcon ID.
	// Returns empty string if not found (not an error).
	GetDefconName(ctx context.Context, defconID string) (string, error)
}

// SensorService implements business logic for sensor operations.
type SensorService struct {
	store          SensorStorer
	vigilNetClient VigilNetClient
	logger         logr.Logger
}

// NewSensorService creates a new SensorService.
func NewSensorService(
	store SensorStorer,
	vigilNetClient VigilNetClient,
	logger logr.Logger,
) *SensorService {
	return &SensorService{
		store:          store,
		vigilNetClient: vigilNetClient,
		logger:         logger,
	}
}

// ListSensorsOptions defines options for listing sensors.
type ListSensorsOptions struct {
	Filter  models.SensorFilter
	Limit   int
	Offset  int
	SortBy  string
	SortAsc bool
}

// ListSensorsResult defines the result of listing sensors.
type ListSensorsResult struct {
	Items      []*models.Sensor
	TotalCount int
	Limit      int
	Offset     int
}

// List returns a paginated list of sensors with optional filtering and Defcon enrichment.
// Implements NH-SM-001: Sensor listing with filtering.
func (s *SensorService) List(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	opts ListSensorsOptions,
) (*ListSensorsResult, error) {
	logger.V(vplogging.LogLevelVerbose).Info("listing sensors",
		"filter.defconId", opts.Filter.DefconID,
		"filter.status", opts.Filter.Status,
		"filter.health", opts.Filter.Health,
		"limit", opts.Limit,
		"offset", opts.Offset)

	// Call store to get sensors
	storeOpts := models.ListSensorsOptions{
		Filter: models.SensorFilter{
			DefconID: opts.Filter.DefconID,
			Status:   opts.Filter.Status,
			Health:   opts.Filter.Health,
		},
		Limit:  opts.Limit,
		Offset: opts.Offset,
	}

	response, err := s.store.List(ctx, storeOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list sensors from store: %w", err)
	}

	// Enrich with Defcon names
	sensors := make([]*models.Sensor, 0, len(response.Items))
	for _, sensor := range response.Items {
		enriched := *sensor

		// Enrich Defcon name if not already set
		if enriched.DefconName == "" && enriched.DefconID != "" {
			defconName, err := s.vigilNetClient.GetDefconName(ctx, enriched.DefconID)
			if err != nil {
				logger.V(vplogging.LogLevelDebug).Info("failed to get defcon name, using defconId",
					"defconId", enriched.DefconID, "error", err)
				// Continue with DefconID as name
				enriched.DefconName = enriched.DefconID
			} else if defconName != "" {
				enriched.DefconName = defconName
			}
		}

		sensors = append(sensors, &enriched)
	}

	result := &ListSensorsResult{
		Items:      sensors,
		TotalCount: response.TotalCount,
		Limit:      response.Limit,
		Offset:     response.Offset,
	}

	return result, nil
}

// Get returns a single sensor by its Picket ID with Defcon enrichment.
// Implements NH-SM-001: Get sensor by ID.
func (s *SensorService) Get(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	picketID string,
) (*models.Sensor, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting sensor by picketId", "picketId", picketID)

	sensor, err := s.store.GetByPicketID(ctx, picketID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor from store: %w", err)
	}

	if sensor == nil {
		return nil, ErrSensorNotFound
	}

	// Enrich Defcon name if not already set
	if sensor.DefconName == "" && sensor.DefconID != "" {
		defconName, err := s.vigilNetClient.GetDefconName(ctx, sensor.DefconID)
		if err != nil {
			logger.V(vplogging.LogLevelDebug).Info("failed to get defcon name, using defconId",
				"defconId", sensor.DefconID, "error", err)
			// Continue with DefconID as name
			sensor.DefconName = sensor.DefconID
		} else if defconName != "" {
			sensor.DefconName = defconName
		}
	}

	return sensor, nil
}

// Register registers a new Picket sensor.
// Implements NH-SM-006: Automatische Registrierung von Pickets.
// Emits audit event per NH-SM-008.
func (s *SensorService) Register(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	sensor *models.Sensor,
) (*models.Sensor, error) {
	logger.V(vplogging.LogLevelVerbose).Info("registering new sensor",
		"picketId", sensor.PicketID,
		"defconId", sensor.DefconID,
		"nodeName", sensor.NodeName)

	// Validate required fields
	if sensor.PicketID == "" {
		return nil, fmt.Errorf("picketId is required: %w", ErrInvalidStatus)
	}
	if sensor.DefconID == "" {
		return nil, fmt.Errorf("defconId is required: %w", ErrInvalidStatus)
	}

	// Check if sensor already exists
	existing, err := s.store.GetByPicketID(ctx, sensor.PicketID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing sensor: %w", err)
	}
	if existing != nil {
		return nil, ErrSensorAlreadyExists
	}

	// Set timestamps
	now := time.Now().UTC()
	sensor.CreatedAt = now
	sensor.UpdatedAt = now

	// Set default status if not set
	if sensor.Status == "" {
		sensor.Status = models.SensorStatusPending
	}

	// Set default health if not set
	if sensor.Health == "" {
		sensor.Health = models.SensorHealthUnknown
	}

	// Enrich Defcon name
	if sensor.DefconName == "" && sensor.DefconID != "" {
		defconName, err := s.vigilNetClient.GetDefconName(ctx, sensor.DefconID)
		if err != nil {
			logger.V(vplogging.LogLevelDebug).Info("failed to get defcon name for new sensor",
				"defconId", sensor.DefconID, "error", err)
			// Continue with DefconID as name
			sensor.DefconName = sensor.DefconID
		} else if defconName != "" {
			sensor.DefconName = defconName
		}
	}

	// Persist sensor
	err = s.store.Create(ctx, sensor)
	if err != nil {
		return nil, fmt.Errorf("failed to create sensor: %w", err)
	}

	// Emit audit event for sensor registration (NH-SM-008)
	s.emitSensorAuditEvent(ctx, subject, "netshield.sensor.register", *sensor)

	return sensor, nil
}

// UpdateStatus updates the operational status and health of a sensor.
// Implements NH-SM-007: Picket-Health-Tracking.
// Emits audit event per NH-SM-008.
func (s *SensorService) UpdateStatus(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	picketID string,
	status models.SensorStatus,
	health models.SensorHealth,
) (*models.Sensor, error) {
	logger.V(vplogging.LogLevelVerbose).Info("updating sensor status and health",
		"picketId", picketID,
		"status", status,
		"health", health)

	// Validate status
	if status != models.SensorStatusPending &&
		status != models.SensorStatusActive &&
		status != models.SensorStatusDegraded &&
		status != models.SensorStatusStale &&
		status != models.SensorStatusError &&
		status != models.SensorStatusDeleting {
		return nil, fmt.Errorf("invalid status %q: %w", status, ErrInvalidStatus)
	}

	// Validate health
	if health != models.SensorHealthHealthy &&
		health != models.SensorHealthUnhealthy &&
		health != models.SensorHealthUnknown {
		return nil, fmt.Errorf("invalid health %q: %w", health, ErrInvalidHealth)
	}

	// Get existing sensor
	sensor, err := s.store.GetByPicketID(ctx, picketID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor: %w", err)
	}
	if sensor == nil {
		return nil, ErrSensorNotFound
	}

	// Update status and health
	oldStatus := sensor.Status
	oldHealth := sensor.Health
	sensor.Status = status
	sensor.Health = health
	sensor.UpdatedAt = time.Now().UTC()

	// Persist update
	err = s.store.Update(ctx, sensor)
	if err != nil {
		return nil, fmt.Errorf("failed to update sensor: %w", err)
	}

	// Emit audit event for status/health change (NH-SM-008)
	meta := map[string]string{
		"previousStatus": string(oldStatus),
		"newStatus":      string(status),
		"previousHealth": string(oldHealth),
		"newHealth":      string(health),
	}
	s.emitSensorAuditEventWithMeta(ctx, subject, "netshield.sensor.status.update", *sensor, meta)

	return sensor, nil
}

// UpdateLastSeen updates the last seen timestamp for a sensor.
// Implements NH-SM-007: Picket-Health-Tracking.
// Emits audit event per NH-SM-008.
func (s *SensorService) UpdateLastSeen(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	picketID string,
) (*models.Sensor, error) {
	logger.V(vplogging.LogLevelVerbose).Info("updating sensor lastSeen", "picketId", picketID)

	// Get existing sensor
	sensor, err := s.store.GetByPicketID(ctx, picketID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor: %w", err)
	}
	if sensor == nil {
		return nil, ErrSensorNotFound
	}

	// Update last seen timestamp
	now := time.Now().UTC()
	oldLastSeen := sensor.LastSeen
	sensor.LastSeen = now
	sensor.UpdatedAt = now

	// Update health based on lastSeen (simplified logic)
	// If we're updating lastSeen, the sensor is at least somewhat healthy
	if sensor.Health == models.SensorHealthUnknown {
		sensor.Health = models.SensorHealthHealthy
	}

	// Persist update
	err = s.store.Update(ctx, sensor)
	if err != nil {
		return nil, fmt.Errorf("failed to update sensor lastSeen: %w", err)
	}

	// Emit audit event for lastSeen update (NH-SM-008)
	meta := map[string]string{
		"previousLastSeen": oldLastSeen.Format(time.RFC3339),
		"newLastSeen":      now.Format(time.RFC3339),
	}
	s.emitSensorAuditEventWithMeta(ctx, subject, "netshield.sensor.lastseen.update", *sensor, meta)

	return sensor, nil
}

// UpdateRuleVersion updates the rule version for a sensor.
// Implements NH-SM-007: Picket-Health-Tracking (rule version tracking).
// Emits audit event per NH-SM-008.
func (s *SensorService) UpdateRuleVersion(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	picketID string,
	version string,
) (*models.Sensor, error) {
	logger.V(vplogging.LogLevelVerbose).Info("updating sensor ruleVersion",
		"picketId", picketID,
		"version", version)

	// Get existing sensor
	sensor, err := s.store.GetByPicketID(ctx, picketID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor: %w", err)
	}
	if sensor == nil {
		return nil, ErrSensorNotFound
	}

	// Update rule version
	oldVersion := sensor.RuleVersion
	sensor.RuleVersion = version
	sensor.UpdatedAt = time.Now().UTC()

	// Persist update
	err = s.store.Update(ctx, sensor)
	if err != nil {
		return nil, fmt.Errorf("failed to update sensor ruleVersion: %w", err)
	}

	// Emit audit event for rule version update (NH-SM-008)
	meta := map[string]string{
		"previousVersion": oldVersion,
		"newVersion":      version,
	}
	s.emitSensorAuditEventWithMeta(ctx, subject, "netshield.sensor.ruleversion.update", *sensor, meta)

	return sensor, nil
}

// GetSensorsByDefcon returns all sensors for a specific Defcon.
// Used for Defcon-scoped operations.
func (s *SensorService) GetSensorsByDefcon(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	defconID string,
) ([]*models.Sensor, error) {
	logger.V(vplogging.LogLevelVerbose).Info("getting sensors by defconId", "defconId", defconID)

	sensors, err := s.store.GetByDefconID(ctx, defconID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensors by defcon: %w", err)
	}

	// Enrich with Defcon names
	for _, sensor := range sensors {
		if sensor.DefconName == "" && sensor.DefconID != "" {
			defconName, err := s.vigilNetClient.GetDefconName(ctx, sensor.DefconID)
			if err != nil {
				logger.V(vplogging.LogLevelDebug).Info("failed to get defcon name",
					"defconId", sensor.DefconID, "error", err)
				sensor.DefconName = sensor.DefconID
			} else if defconName != "" {
				sensor.DefconName = defconName
			}
		}
	}

	return sensors, nil
}

// MarkStale marks sensors that have not sent events within the stale threshold.
// Implements NH-SM-007: Picket-Health-Tracking (stale detection).
// Emits audit event per NH-SM-008.
func (s *SensorService) MarkStale(
	ctx context.Context,
	logger logr.Logger,
	subject *types.Subject,
	staleThreshold time.Duration,
) (int, error) {
	logger.V(vplogging.LogLevelVerbose).Info("marking stale sensors", "threshold", staleThreshold)

	// Get all sensors
	sensors, err := s.store.List(ctx, models.ListSensorsOptions{
		Filter: models.SensorFilter{
			Status: string(models.SensorStatusActive),
		},
		Limit:  0, // No limit
		Offset: 0,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list sensors: %w", err)
	}

	now := time.Now().UTC()
	staleCount := 0

	for _, sensor := range sensors.Items {
		// Skip if already stale or in other terminal states
		if sensor.Status == models.SensorStatusStale ||
			sensor.Status == models.SensorStatusDeleting ||
			sensor.Status == models.SensorStatusError {
			continue
		}

		// Check if sensor is stale
		if now.Sub(sensor.LastSeen) > staleThreshold {
			oldStatus := sensor.Status
			sensor.Status = models.SensorStatusStale
			sensor.Health = models.SensorHealthUnhealthy
			sensor.UpdatedAt = now

			err := s.store.Update(ctx, sensor)
			if err != nil {
				logger.V(vplogging.LogLevelDebug).Info("failed to mark sensor as stale",
					"picketId", sensor.PicketID, "error", err)
				continue
			}

			// Emit audit event for stale marking (NH-SM-008)
			meta := map[string]string{
				"previousStatus": string(oldStatus),
				"newStatus":      string(models.SensorStatusStale),
				"reason":         "no events received within stale threshold",
			}
			s.emitSensorAuditEventWithMeta(ctx, subject, "netshield.sensor.stale", *sensor, meta)

			staleCount++
		}
	}

	logger.V(vplogging.LogLevelVerbose).Info("marked sensors as stale", "count", staleCount)

	return staleCount, nil
}

// emitSensorAuditEvent emits an audit event for sensor operations.
// Helper for NH-SM-008: Audit-Events fuer Picket-Register/Stale.
func (s *SensorService) emitSensorAuditEvent(
	ctx context.Context,
	subject *types.Subject,
	action string,
	sensor models.Sensor,
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
			Type: "netshield.sensor",
			ID:   sensor.PicketID,
		},
		Result: ironchronicle.ResultSuccess,
		Meta: map[string]string{
			"defconId":    sensor.DefconID,
			"defconName":  sensor.DefconName,
			"nodeName":    sensor.NodeName,
			"namespace":   sensor.Namespace,
			"status":      string(sensor.Status),
			"health":      string(sensor.Health),
			"ruleVersion": sensor.RuleVersion,
		},
	}

	ironchronicle.Emit(ctx, event)
}

// emitSensorAuditEventWithMeta emits an audit event with additional metadata.
// Helper for NH-SM-008: Audit-Events fuer Picket-Register/Stale.
func (s *SensorService) emitSensorAuditEventWithMeta(
	ctx context.Context,
	subject *types.Subject,
	action string,
	sensor models.Sensor,
	meta map[string]string,
) {
	// Merge base meta with additional meta
	mergedMeta := map[string]string{
		"defconId":    sensor.DefconID,
		"defconName":  sensor.DefconName,
		"nodeName":    sensor.NodeName,
		"namespace":   sensor.Namespace,
		"status":      string(sensor.Status),
		"health":      string(sensor.Health),
		"ruleVersion": sensor.RuleVersion,
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
			Type: "netshield.sensor",
			ID:   sensor.PicketID,
		},
		Result: ironchronicle.ResultSuccess,
		Meta:   mergedMeta,
	}

	ironchronicle.Emit(ctx, event)
}


