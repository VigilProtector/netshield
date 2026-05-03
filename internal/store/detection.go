// Package store provides the data access layer for NetShield.
// Uses MongoDB for persistence.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"vigilprotector.io/netshield/internal/models"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// Errors for the detection store.
var (
	// ErrDetectionNotFound is returned when a detection is not found.
	ErrDetectionNotFound = errors.New("detection not found")
	// ErrDetectionAlreadyExists is returned when a detection already exists.
	ErrDetectionAlreadyExists = errors.New("detection already exists")
)

// DetectionStore implements DetectionStorer interface for MongoDB persistence.
type DetectionStore struct {
	collection *mongo.Collection
	logger     logr.Logger
}

// NewDetectionStore creates a new DetectionStore.
func NewDetectionStore(collection *mongo.Collection, logger logr.Logger) *DetectionStore {
	return &DetectionStore{
		collection: collection,
		logger:     logger,
	}
}

// List returns a paginated list of detections with optional filtering.
// Implements DetectionStorer interface.
func (s *DetectionStore) List(
	ctx context.Context,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("listing detections from store",
		"filter.sensorId", opts.Filter.SensorID,
		"filter.picketId", opts.Filter.PicketID,
		"filter.ruleSetId", opts.Filter.RuleSetID,
		"filter.ruleId", opts.Filter.RuleID,
		"filter.eventType", opts.Filter.EventType,
		"filter.severity", opts.Filter.Severity,
		"limit", opts.Limit,
		"offset", opts.Offset)

	// Build filter
	filter := bson.M{}

	if opts.Filter.SensorID != "" {
		filter["sensorId"] = opts.Filter.SensorID
	}

	if opts.Filter.PicketID != "" {
		filter["picketId"] = opts.Filter.PicketID
	}

	if opts.Filter.RuleSetID != "" {
		filter["ruleSetId"] = opts.Filter.RuleSetID
	}

	if opts.Filter.RuleID != "" {
		filter["ruleId"] = opts.Filter.RuleID
	}

	if opts.Filter.EventType != "" {
		filter["eventType"] = opts.Filter.EventType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	// Handle time range filters
	if opts.Filter.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, opts.Filter.StartTime)
		if err == nil {
			filter["timestamp"] = bson.M{"$gte": startTime}
		}
	}

	if opts.Filter.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, opts.Filter.EndTime)
		if err == nil {
			if _, hasGte := filter["timestamp"]; hasGte {
				// Merge with existing timestamp filter
				filter["timestamp"] = bson.M{
					"$gte": filter["timestamp"].(bson.M)["$gte"],
					"$lte": endTime,
				}
			} else {
				filter["timestamp"] = bson.M{"$lte": endTime}
			}
		}
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count detections: %w", err)
	}

	// Apply pagination and sorting
	findOpts := options.Find()
	if opts.Limit > 0 {
		findOpts.SetLimit(int64(opts.Limit))
	}

	if opts.Offset > 0 {
		findOpts.SetSkip(int64(opts.Offset))
	}

	// Apply sorting (default by timestamp descending)
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sortOrder := -1 // Default descending for detections
	if opts.SortAsc {
		sortOrder = 1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find detections: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	detections := make([]*models.Detection, 0)

	for cursor.Next(ctx) {
		var detection models.Detection
		if err := cursor.Decode(&detection); err != nil {
			return nil, fmt.Errorf("failed to decode detection: %w", err)
		}

		detections = append(detections, &detection)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.DetectionListResponse{
		Items:      detections,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByID returns a single detection by its MongoDB ID.
// Implements DetectionStorer interface.
func (s *DetectionStore) GetByID(
	ctx context.Context,
	id string,
) (*models.Detection, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting detection by id from store", "id", id)

	objID, err := bsonObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid id format: %w", err)
	}

	filter := bson.M{"_id": objID}

	var detection models.Detection

	err = s.collection.FindOne(ctx, filter).Decode(&detection)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get detection by id: %w", err)
	}

	return &detection, nil
}

// GetByDetectionID returns a single detection by its detection ID.
// Implements DetectionStorer interface.
func (s *DetectionStore) GetByDetectionID(
	ctx context.Context,
	detectionID string,
) (*models.Detection, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting detection by detectionId from store", "detectionId", detectionID)

	filter := bson.M{"detectionId": detectionID}

	var detection models.Detection

	err := s.collection.FindOne(ctx, filter).Decode(&detection)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get detection by detectionId: %w", err)
	}

	return &detection, nil
}

// Create creates a new detection.
// Implements DetectionStorer interface.
func (s *DetectionStore) Create(
	ctx context.Context,
	detection *models.Detection,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("creating detection in store",
		"detectionId", detection.DetectionID,
		"sensorId", detection.SensorID,
		"picketId", detection.PicketID,
		"eventType", detection.EventType)

	// Insert detection
	_, err := s.collection.InsertOne(ctx, detection)
	if err != nil {
		// Check for duplicate key error
		var dupKeyErr mongo.WriteException
		if errors.As(err, &dupKeyErr) {
			for _, we := range dupKeyErr.WriteErrors {
				if we.Code == 11000 {
					return ErrDetectionAlreadyExists
				}
			}
		}

		return fmt.Errorf("failed to create detection: %w", err)
	}

	return nil
}

// Update updates an existing detection.
// Implements DetectionStorer interface.
func (s *DetectionStore) Update(
	ctx context.Context,
	detection *models.Detection,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("updating detection in store",
		"detectionId", detection.DetectionID,
		"id", detection.ID.Hex())

	// Build update
	filter := bson.M{"_id": detection.ID}
	update := bson.M{
		"$set": bson.M{
			"detectionId":  detection.DetectionID,
			"sensorId":     detection.SensorID,
			"picketId":     detection.PicketID,
			"ruleSetId":    detection.RuleSetID,
			"ruleVersion":  detection.RuleVersion,
			"ruleId":       detection.RuleID,
			"eventType":    detection.EventType,
			"timestamp":    detection.Timestamp,
			"sourceIp":     detection.SourceIP,
			"destIp":       detection.DestIP,
			"sourcePort":   detection.SourcePort,
			"destPort":     detection.DestPort,
			"proto":        detection.Proto,
			"action":       detection.Action,
			"signature":    detection.Signature,
			"category":     detection.Category,
			"severity":     detection.Severity,
			"confidence":   detection.Confidence,
			"message":      detection.Message,
			"rawEvent":     detection.RawEvent,
			"evidenceRefs": detection.EvidenceRefs,
			"assetId":      detection.AssetID,
			"defconId":     detection.DefconID,
			"createdAt":    detection.CreatedAt,
			"updatedAt":    detection.UpdatedAt,
		},
	}

	// Execute update
	result, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update detection: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrDetectionNotFound
	}

	return nil
}

// Delete deletes a detection by its ID.
// Implements DetectionStorer interface.
func (s *DetectionStore) Delete(
	ctx context.Context,
	id string,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("deleting detection from store", "id", id)

	objID, err := bsonObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("invalid id format: %w", err)
	}

	filter := bson.M{"_id": objID}

	result, err := s.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete detection: %w", err)
	}

	if result.DeletedCount == 0 {
		return ErrDetectionNotFound
	}

	return nil
}

// GetBySensorID returns detections for a specific sensor.
// Implements DetectionStorer interface.
func (s *DetectionStore) GetBySensorID(
	ctx context.Context,
	sensorID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting detections by sensorId from store", "sensorId", sensorID)

	// Build filter
	filter := bson.M{"sensorId": sensorID}

	// Apply additional filters from opts
	if opts.Filter.PicketID != "" {
		filter["picketId"] = opts.Filter.PicketID
	}

	if opts.Filter.RuleSetID != "" {
		filter["ruleSetId"] = opts.Filter.RuleSetID
	}

	if opts.Filter.RuleID != "" {
		filter["ruleId"] = opts.Filter.RuleID
	}

	if opts.Filter.EventType != "" {
		filter["eventType"] = opts.Filter.EventType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	// Handle time range filters
	if opts.Filter.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, opts.Filter.StartTime)
		if err == nil {
			filter["timestamp"] = bson.M{"$gte": startTime}
		}
	}

	if opts.Filter.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, opts.Filter.EndTime)
		if err == nil {
			if _, hasGte := filter["timestamp"]; hasGte {
				filter["timestamp"] = bson.M{
					"$gte": filter["timestamp"].(bson.M)["$gte"],
					"$lte": endTime,
				}
			} else {
				filter["timestamp"] = bson.M{"$lte": endTime}
			}
		}
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count detections: %w", err)
	}

	// Apply pagination
	findOpts := options.Find()
	if opts.Limit > 0 {
		findOpts.SetLimit(int64(opts.Limit))
	}

	if opts.Offset > 0 {
		findOpts.SetSkip(int64(opts.Offset))
	}

	// Apply sorting
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sortOrder := -1
	if opts.SortAsc {
		sortOrder = 1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find detections by sensor: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	detections := make([]*models.Detection, 0)

	for cursor.Next(ctx) {
		var detection models.Detection
		if err := cursor.Decode(&detection); err != nil {
			return nil, fmt.Errorf("failed to decode detection: %w", err)
		}

		detections = append(detections, &detection)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.DetectionListResponse{
		Items:      detections,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByPicketID returns detections for a specific Picket.
// Implements DetectionStorer interface.
func (s *DetectionStore) GetByPicketID(
	ctx context.Context,
	picketID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting detections by picketId from store", "picketId", picketID)

	// Build filter
	filter := bson.M{"picketId": picketID}

	// Apply additional filters from opts
	if opts.Filter.SensorID != "" {
		filter["sensorId"] = opts.Filter.SensorID
	}

	if opts.Filter.RuleSetID != "" {
		filter["ruleSetId"] = opts.Filter.RuleSetID
	}

	if opts.Filter.RuleID != "" {
		filter["ruleId"] = opts.Filter.RuleID
	}

	if opts.Filter.EventType != "" {
		filter["eventType"] = opts.Filter.EventType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	// Handle time range filters
	if opts.Filter.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, opts.Filter.StartTime)
		if err == nil {
			filter["timestamp"] = bson.M{"$gte": startTime}
		}
	}

	if opts.Filter.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, opts.Filter.EndTime)
		if err == nil {
			if _, hasGte := filter["timestamp"]; hasGte {
				filter["timestamp"] = bson.M{
					"$gte": filter["timestamp"].(bson.M)["$gte"],
					"$lte": endTime,
				}
			} else {
				filter["timestamp"] = bson.M{"$lte": endTime}
			}
		}
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count detections: %w", err)
	}

	// Apply pagination
	findOpts := options.Find()
	if opts.Limit > 0 {
		findOpts.SetLimit(int64(opts.Limit))
	}

	if opts.Offset > 0 {
		findOpts.SetSkip(int64(opts.Offset))
	}

	// Apply sorting
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sortOrder := -1
	if opts.SortAsc {
		sortOrder = 1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find detections by picket: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	detections := make([]*models.Detection, 0)

	for cursor.Next(ctx) {
		var detection models.Detection
		if err := cursor.Decode(&detection); err != nil {
			return nil, fmt.Errorf("failed to decode detection: %w", err)
		}

		detections = append(detections, &detection)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.DetectionListResponse{
		Items:      detections,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByRuleSetID returns detections for a specific rule set.
// Implements DetectionStorer interface.
func (s *DetectionStore) GetByRuleSetID(
	ctx context.Context,
	ruleSetID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting detections by ruleSetId from store", "ruleSetId", ruleSetID)

	// Build filter
	filter := bson.M{"ruleSetId": ruleSetID}

	// Apply additional filters from opts
	if opts.Filter.SensorID != "" {
		filter["sensorId"] = opts.Filter.SensorID
	}

	if opts.Filter.PicketID != "" {
		filter["picketId"] = opts.Filter.PicketID
	}

	if opts.Filter.RuleID != "" {
		filter["ruleId"] = opts.Filter.RuleID
	}

	if opts.Filter.EventType != "" {
		filter["eventType"] = opts.Filter.EventType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	// Handle time range filters
	if opts.Filter.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, opts.Filter.StartTime)
		if err == nil {
			filter["timestamp"] = bson.M{"$gte": startTime}
		}
	}

	if opts.Filter.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, opts.Filter.EndTime)
		if err == nil {
			if _, hasGte := filter["timestamp"]; hasGte {
				filter["timestamp"] = bson.M{
					"$gte": filter["timestamp"].(bson.M)["$gte"],
					"$lte": endTime,
				}
			} else {
				filter["timestamp"] = bson.M{"$lte": endTime}
			}
		}
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count detections: %w", err)
	}

	// Apply pagination
	findOpts := options.Find()
	if opts.Limit > 0 {
		findOpts.SetLimit(int64(opts.Limit))
	}

	if opts.Offset > 0 {
		findOpts.SetSkip(int64(opts.Offset))
	}

	// Apply sorting
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sortOrder := -1
	if opts.SortAsc {
		sortOrder = 1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find detections by ruleSet: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	detections := make([]*models.Detection, 0)

	for cursor.Next(ctx) {
		var detection models.Detection
		if err := cursor.Decode(&detection); err != nil {
			return nil, fmt.Errorf("failed to decode detection: %w", err)
		}

		detections = append(detections, &detection)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.DetectionListResponse{
		Items:      detections,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByRuleID returns detections for a specific rule.
// Implements DetectionStorer interface.
func (s *DetectionStore) GetByRuleID(
	ctx context.Context,
	ruleID string,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting detections by ruleId from store", "ruleId", ruleID)

	// Build filter
	filter := bson.M{"ruleId": ruleID}

	// Apply additional filters from opts
	if opts.Filter.SensorID != "" {
		filter["sensorId"] = opts.Filter.SensorID
	}

	if opts.Filter.PicketID != "" {
		filter["picketId"] = opts.Filter.PicketID
	}

	if opts.Filter.RuleSetID != "" {
		filter["ruleSetId"] = opts.Filter.RuleSetID
	}

	if opts.Filter.EventType != "" {
		filter["eventType"] = opts.Filter.EventType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	// Handle time range filters
	if opts.Filter.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, opts.Filter.StartTime)
		if err == nil {
			filter["timestamp"] = bson.M{"$gte": startTime}
		}
	}

	if opts.Filter.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, opts.Filter.EndTime)
		if err == nil {
			if _, hasGte := filter["timestamp"]; hasGte {
				filter["timestamp"] = bson.M{
					"$gte": filter["timestamp"].(bson.M)["$gte"],
					"$lte": endTime,
				}
			} else {
				filter["timestamp"] = bson.M{"$lte": endTime}
			}
		}
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count detections: %w", err)
	}

	// Apply pagination
	findOpts := options.Find()
	if opts.Limit > 0 {
		findOpts.SetLimit(int64(opts.Limit))
	}

	if opts.Offset > 0 {
		findOpts.SetSkip(int64(opts.Offset))
	}

	// Apply sorting
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sortOrder := -1
	if opts.SortAsc {
		sortOrder = 1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find detections by rule: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	detections := make([]*models.Detection, 0)

	for cursor.Next(ctx) {
		var detection models.Detection
		if err := cursor.Decode(&detection); err != nil {
			return nil, fmt.Errorf("failed to decode detection: %w", err)
		}

		detections = append(detections, &detection)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.DetectionListResponse{
		Items:      detections,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetUnprocessed returns detections that have not been processed yet.
// Implements DetectionStorer interface.
func (s *DetectionStore) GetUnprocessed(
	ctx context.Context,
	opts models.ListDetectionsOptions,
) (*models.DetectionListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting unprocessed detections from store")

	// Build filter - detections without associated findings
	// We use a simple approach: check if the detection has been processed
	// In a real implementation, we might have a processed flag or check for finding references
	// For now, we'll return all detections and let the service layer filter
	filter := bson.M{}

	// Apply filters from opts
	if opts.Filter.SensorID != "" {
		filter["sensorId"] = opts.Filter.SensorID
	}

	if opts.Filter.PicketID != "" {
		filter["picketId"] = opts.Filter.PicketID
	}

	if opts.Filter.RuleSetID != "" {
		filter["ruleSetId"] = opts.Filter.RuleSetID
	}

	if opts.Filter.RuleID != "" {
		filter["ruleId"] = opts.Filter.RuleID
	}

	if opts.Filter.EventType != "" {
		filter["eventType"] = opts.Filter.EventType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	// Handle time range filters
	if opts.Filter.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, opts.Filter.StartTime)
		if err == nil {
			filter["timestamp"] = bson.M{"$gte": startTime}
		}
	}

	if opts.Filter.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, opts.Filter.EndTime)
		if err == nil {
			if _, hasGte := filter["timestamp"]; hasGte {
				filter["timestamp"] = bson.M{
					"$gte": filter["timestamp"].(bson.M)["$gte"],
					"$lte": endTime,
				}
			} else {
				filter["timestamp"] = bson.M{"$lte": endTime}
			}
		}
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count detections: %w", err)
	}

	// Apply pagination
	findOpts := options.Find()
	if opts.Limit > 0 {
		findOpts.SetLimit(int64(opts.Limit))
	}

	if opts.Offset > 0 {
		findOpts.SetSkip(int64(opts.Offset))
	}

	// Apply sorting
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sortOrder := -1
	if opts.SortAsc {
		sortOrder = 1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find unprocessed detections: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	detections := make([]*models.Detection, 0)

	for cursor.Next(ctx) {
		var detection models.Detection
		if err := cursor.Decode(&detection); err != nil {
			return nil, fmt.Errorf("failed to decode detection: %w", err)
		}

		detections = append(detections, &detection)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.DetectionListResponse{
		Items:      detections,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// EnsureIndex creates the necessary indexes for the detection collection.
func (s *DetectionStore) EnsureIndex(ctx context.Context) error {
	s.logger.V(vplogging.LogLevelInfo).Info("ensuring indexes for detection collection")

	// Create unique index on detectionId
	detectionIDIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "detectionId", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	// Create index on sensorId
	sensorIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "sensorId", Value: 1}},
	}

	// Create index on picketId
	picketIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "picketId", Value: 1}},
	}

	// Create index on ruleSetId
	ruleSetIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "ruleSetId", Value: 1}},
	}

	// Create index on ruleId
	ruleIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "ruleId", Value: 1}},
	}

	// Create index on eventType
	eventTypeIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "eventType", Value: 1}},
	}

	// Create index on severity
	severityIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "severity", Value: 1}},
	}

	// Create index on timestamp for time-based queries
	timestampIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "timestamp", Value: -1}},
	}

	// Create index on createdAt
	createdAtIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "createdAt", Value: -1}},
	}

	// Create index on sourceIp for flow correlation
	sourceIPIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "sourceIp", Value: 1}},
	}

	// Create index on destIp
	destIPIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "destIp", Value: 1}},
	}

	// Create index on assetId
	assetIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "assetId", Value: 1}},
	}

	// Create index on defconId
	defconIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "defconId", Value: 1}},
	}

	// Create compound index for common query patterns
	compoundQueryIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "sensorId", Value: 1},
			{Key: "picketId", Value: 1},
			{Key: "timestamp", Value: -1},
		},
	}

	// Create compound index for rule-based queries
	compoundRuleIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "ruleSetId", Value: 1},
			{Key: "ruleId", Value: 1},
			{Key: "timestamp", Value: -1},
		},
	}

	// Create indexes
	_, err := s.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		detectionIDIndex,
		sensorIDIndex,
		picketIDIndex,
		ruleSetIDIndex,
		ruleIDIndex,
		eventTypeIndex,
		severityIndex,
		timestampIndex,
		createdAtIndex,
		sourceIPIndex,
		destIPIndex,
		assetIDIndex,
		defconIDIndex,
		compoundQueryIndex,
		compoundRuleIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}
