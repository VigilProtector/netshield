// Package store provides the data access layer for NetShield.
// Uses MongoDB for persistence.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"vigilprotector.io/netshield/internal/models"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// Errors for the sensor store.
var (
	// ErrSensorNotFound is returned when a sensor is not found.
	ErrSensorNotFound = errors.New("sensor not found")
	// ErrSensorAlreadyExists is returned when a sensor already exists.
	ErrSensorAlreadyExists = errors.New("sensor already exists")
	// ErrInvalidID is returned when an invalid ID is provided.
	ErrInvalidID = errors.New("invalid ID")
)

// SensorStore implements SensorStorer interface for MongoDB persistence.
type SensorStore struct {
	collection *mongo.Collection
	logger     logr.Logger
}

// NewSensorStore creates a new SensorStore.
func NewSensorStore(collection *mongo.Collection, logger logr.Logger) *SensorStore {
	return &SensorStore{
		collection: collection,
		logger:     logger,
	}
}

// List returns a paginated list of sensors with optional filtering.
// Implements SensorStorer interface.
func (s *SensorStore) List(
	ctx context.Context,
	opts models.ListSensorsOptions,
) (*models.SensorListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("listing sensors from store",
		"filter.defconId", opts.Filter.DefconID,
		"filter.status", opts.Filter.Status,
		"filter.health", opts.Filter.Health,
		"limit", opts.Limit,
		"offset", opts.Offset)

	// Build filter
	filter := bson.M{}

	if opts.Filter.DefconID != "" {
		filter["defconId"] = opts.Filter.DefconID
	}

	if opts.Filter.Status != "" {
		filter["status"] = opts.Filter.Status
	}

	if opts.Filter.Health != "" {
		filter["health"] = opts.Filter.Health
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count sensors: %w", err)
	}

	// Apply pagination
	findOpts := options.Find()
	if opts.Limit > 0 {
		findOpts.SetLimit(int64(opts.Limit))
	}

	if opts.Offset > 0 {
		findOpts.SetSkip(int64(opts.Offset))
	}

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find sensors: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	sensors := make([]*models.Sensor, 0)

	for cursor.Next(ctx) {
		var sensor models.Sensor
		if err := cursor.Decode(&sensor); err != nil {
			return nil, fmt.Errorf("failed to decode sensor: %w", err)
		}

		sensors = append(sensors, &sensor)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.SensorListResponse{
		Items:      sensors,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByPicketID returns a single sensor by its Picket ID.
// Implements SensorStorer interface.
func (s *SensorStore) GetByPicketID(
	ctx context.Context,
	picketID string,
) (*models.Sensor, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting sensor by picketId from store", "picketId", picketID)

	filter := bson.M{"picketId": picketID}

	var sensor models.Sensor

	err := s.collection.FindOne(ctx, filter).Decode(&sensor)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get sensor by picketId: %w", err)
	}

	return &sensor, nil
}

// Create creates a new sensor.
// Implements SensorStorer interface.
func (s *SensorStore) Create(
	ctx context.Context,
	sensor *models.Sensor,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("creating sensor in store",
		"picketId", sensor.PicketID,
		"defconId", sensor.DefconID)

	// Insert sensor
	_, err := s.collection.InsertOne(ctx, sensor)
	if err != nil {
		// Check for duplicate key error
		var dupKeyErr mongo.WriteException
		if errors.As(err, &dupKeyErr) {
			for _, we := range dupKeyErr.WriteErrors {
				if we.Code == 11000 {
					return ErrSensorAlreadyExists
				}
			}
		}

		return fmt.Errorf("failed to create sensor: %w", err)
	}

	return nil
}

// Update updates an existing sensor.
// Implements SensorStorer interface.
func (s *SensorStore) Update(
	ctx context.Context,
	sensor *models.Sensor,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("updating sensor in store",
		"picketId", sensor.PicketID,
		"defconId", sensor.DefconID)

	// Build update
	filter := bson.M{"picketId": sensor.PicketID}
	update := bson.M{
		"$set": bson.M{
			"defconId":    sensor.DefconID,
			"defconName":  sensor.DefconName,
			"nodeName":    sensor.NodeName,
			"namespace":   sensor.Namespace,
			"status":      sensor.Status,
			"health":      sensor.Health,
			"ruleVersion": sensor.RuleVersion,
			"lastSeen":    sensor.LastSeen,
			"updatedAt":   sensor.UpdatedAt,
			"updatedBy":   sensor.UpdatedBy,
		},
	}

	// Execute update
	result, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update sensor: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrSensorNotFound
	}

	return nil
}

// GetByDefconID returns sensors for a specific Defcon.
// Implements SensorStorer interface.
func (s *SensorStore) GetByDefconID(
	ctx context.Context,
	defconID string,
) ([]*models.Sensor, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting sensors by defconId from store", "defconId", defconID)

	filter := bson.M{"defconId": defconID}

	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find sensors by defconId: %w", err)
	}
	defer cursor.Close(ctx)

	sensors := make([]*models.Sensor, 0)

	for cursor.Next(ctx) {
		var sensor models.Sensor
		if err := cursor.Decode(&sensor); err != nil {
			return nil, fmt.Errorf("failed to decode sensor: %w", err)
		}

		sensors = append(sensors, &sensor)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return sensors, nil
}

// EnsureIndex creates the necessary indexes for the sensor collection.
func (s *SensorStore) EnsureIndex(ctx context.Context) error {
	s.logger.V(vplogging.LogLevelInfo).Info("ensuring indexes for sensor collection")

	// Create unique index on picketId
	picketIDIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "picketId", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	// Create index on defconId
	defconIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "defconId", Value: 1}},
	}

	// Create index on status
	statusIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "status", Value: 1}},
	}

	// Create index on health
	healthIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "health", Value: 1}},
	}

	// Create compound index on defconId + status + health for filtering
	compoundIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "defconId", Value: 1},
			{Key: "status", Value: 1},
			{Key: "health", Value: 1},
		},
	}

	// Create indexes
	_, err := s.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		picketIDIndex,
		defconIDIndex,
		statusIndex,
		healthIndex,
		compoundIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}
