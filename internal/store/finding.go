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

// Errors for the finding store.
var (
	// ErrFindingNotFound is returned when a finding is not found.
	ErrFindingNotFound = errors.New("finding not found")
	// ErrFindingAlreadyExists is returned when a finding already exists.
	ErrFindingAlreadyExists = errors.New("finding already exists")
)

// FindingStore implements FindingStorer interface for MongoDB persistence.
type FindingStore struct {
	collection *mongo.Collection
	logger     logr.Logger
}

// NewFindingStore creates a new FindingStore.
func NewFindingStore(collection *mongo.Collection, logger logr.Logger) *FindingStore {
	return &FindingStore{
		collection: collection,
		logger:     logger,
	}
}

// List returns a paginated list of findings with optional filtering.
// Implements FindingStorer interface.
func (s *FindingStore) List(
	ctx context.Context,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("listing findings from store",
		"filter.findingType", opts.Filter.FindingType,
		"filter.sourceContext", opts.Filter.SourceContext,
		"filter.assetId", opts.Filter.AssetID,
		"filter.defconId", opts.Filter.DefconID,
		"filter.severity", opts.Filter.Severity,
		"filter.lifecycle", opts.Filter.Lifecycle,
		"filter.verification", opts.Filter.Verification,
		"filter.freshness", opts.Filter.Freshness,
		"limit", opts.Limit,
		"offset", opts.Offset)

	// Build filter
	filter := bson.M{}

	if opts.Filter.FindingType != "" {
		filter["findingType"] = opts.Filter.FindingType
	}

	if opts.Filter.SourceContext != "" {
		filter["sourceContext"] = opts.Filter.SourceContext
	}

	if opts.Filter.AssetID != "" {
		filter["assetId"] = opts.Filter.AssetID
	}

	if opts.Filter.DefconID != "" {
		filter["defconId"] = opts.Filter.DefconID
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	if opts.Filter.Lifecycle != "" {
		filter["lifecycle.status"] = opts.Filter.Lifecycle
	}

	if opts.Filter.Verification != "" {
		filter["verification.status"] = opts.Filter.Verification
	}

	if opts.Filter.Freshness != "" {
		filter["freshness.status"] = opts.Filter.Freshness
	}

	// Handle time range filters
	if opts.Filter.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, opts.Filter.StartTime)
		if err == nil {
			filter["occurredAt"] = bson.M{"$gte": startTime}
		}
	}

	if opts.Filter.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, opts.Filter.EndTime)
		if err == nil {
			if _, hasGte := filter["occurredAt"]; hasGte {
				// Merge with existing occurredAt filter
				filter["occurredAt"] = bson.M{
					"$gte": filter["occurredAt"].(bson.M)["$gte"],
					"$lte": endTime,
				}
			} else {
				filter["occurredAt"] = bson.M{"$lte": endTime}
			}
		}
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
	}

	// Apply pagination and sorting
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
		sortBy = "occurredAt"
	}

	sortOrder := 1
	if !opts.SortAsc {
		sortOrder = -1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find findings: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored

	// Decode results
	findings := make([]*models.Finding, 0)

	for cursor.Next(ctx) {
		var finding models.Finding
		if err := cursor.Decode(&finding); err != nil {
			return nil, fmt.Errorf("failed to decode finding: %w", err)
		}

		findings = append(findings, &finding)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.FindingListResponse{
		Items:      findings,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByID returns a single finding by its MongoDB ID.
// Implements FindingStorer interface.
func (s *FindingStore) GetByID(
	ctx context.Context,
	id string,
) (*models.Finding, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting finding by id from store", "id", id)

	objID, err := bsonObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid id format: %w", err)
	}

	filter := bson.M{"_id": objID}

	var finding models.Finding

	err = s.collection.FindOne(ctx, filter).Decode(&finding)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get finding by id: %w", err)
	}

	return &finding, nil
}

// GetByFindingID returns a single finding by its finding ID.
// Implements FindingStorer interface.
func (s *FindingStore) GetByFindingID(
	ctx context.Context,
	findingID string,
) (*models.Finding, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting finding by findingId from store", "findingId", findingID)

	filter := bson.M{"findingId": findingID}

	var finding models.Finding

	err := s.collection.FindOne(ctx, filter).Decode(&finding)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get finding by findingId: %w", err)
	}

	return &finding, nil
}

// Create creates a new finding.
// Implements FindingStorer interface.
func (s *FindingStore) Create(
	ctx context.Context,
	finding *models.Finding,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("creating finding in store",
		"findingId", finding.FindingID,
		"findingType", finding.FindingType,
		"severity", finding.Severity)

	// Insert finding
	_, err := s.collection.InsertOne(ctx, finding)
	if err != nil {
		// Check for duplicate key error
		var dupKeyErr mongo.WriteException
		if errors.As(err, &dupKeyErr) {
			for _, we := range dupKeyErr.WriteErrors {
				if we.Code == 11000 {
					return ErrFindingAlreadyExists
				}
			}
		}

		return fmt.Errorf("failed to create finding: %w", err)
	}

	return nil
}

// Update updates an existing finding.
// Implements FindingStorer interface.
func (s *FindingStore) Update(
	ctx context.Context,
	finding *models.Finding,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("updating finding in store",
		"findingId", finding.FindingID,
		"id", finding.ID.Hex())

	// Build update
	filter := bson.M{"_id": finding.ID}
	update := bson.M{
		"$set": bson.M{
			"findingId":     finding.FindingID,
			"schemaVersion": finding.SchemaVersion,
			"findingType":   finding.FindingType,
			"sourceContext": finding.SourceContext,
			"assetId":       finding.AssetID,
			"defconId":      finding.DefconID,
			"occurredAt":    finding.OccurredAt,
			"window":        finding.Window,
			"severity":      finding.Severity,
			"confidence":    finding.Confidence,
			"title":         finding.Title,
			"description":   finding.Description,
			"attributes":    finding.Attributes,
			"evidenceRefs":  finding.EvidenceRefs,
			"correlation":   finding.Correlation,
			"lifecycle":     finding.Lifecycle,
			"verification":  finding.Verification,
			"freshness":     finding.Freshness,
			"createdAt":     finding.CreatedAt,
			"updatedAt":     finding.UpdatedAt,
		},
	}

	// Execute update
	result, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrFindingNotFound
	}

	return nil
}

// Delete deletes a finding by its ID.
// Implements FindingStorer interface.
func (s *FindingStore) Delete(
	ctx context.Context,
	id string,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("deleting finding from store", "id", id)

	objID, err := bsonObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("invalid id format: %w", err)
	}

	filter := bson.M{"_id": objID}

	result, err := s.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete finding: %w", err)
	}

	if result.DeletedCount == 0 {
		return ErrFindingNotFound
	}

	return nil
}

// GetByAssetID returns findings for a specific asset.
// Implements FindingStorer interface.
func (s *FindingStore) GetByAssetID(
	ctx context.Context,
	assetID string,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting findings by assetId from store", "assetId", assetID)

	// Build filter
	filter := bson.M{"assetId": assetID}

	// Apply additional filters from opts
	if opts.Filter.FindingType != "" {
		filter["findingType"] = opts.Filter.FindingType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	if opts.Filter.Lifecycle != "" {
		filter["lifecycle.status"] = opts.Filter.Lifecycle
	}

	if opts.Filter.Verification != "" {
		filter["verification.status"] = opts.Filter.Verification
	}

	if opts.Filter.Freshness != "" {
		filter["freshness.status"] = opts.Filter.Freshness
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
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
		sortBy = "occurredAt"
	}

	sortOrder := 1
	if !opts.SortAsc {
		sortOrder = -1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find findings by asset: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored

	// Decode results
	findings := make([]*models.Finding, 0)

	for cursor.Next(ctx) {
		var finding models.Finding
		if err := cursor.Decode(&finding); err != nil {
			return nil, fmt.Errorf("failed to decode finding: %w", err)
		}

		findings = append(findings, &finding)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.FindingListResponse{
		Items:      findings,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByDefconID returns findings for a specific Defcon.
// Implements FindingStorer interface.
func (s *FindingStore) GetByDefconID(
	ctx context.Context,
	defconID string,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting findings by defconId from store", "defconId", defconID)

	// Build filter
	filter := bson.M{"defconId": defconID}

	// Apply additional filters from opts
	if opts.Filter.FindingType != "" {
		filter["findingType"] = opts.Filter.FindingType
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	if opts.Filter.Lifecycle != "" {
		filter["lifecycle.status"] = opts.Filter.Lifecycle
	}

	if opts.Filter.Verification != "" {
		filter["verification.status"] = opts.Filter.Verification
	}

	if opts.Filter.Freshness != "" {
		filter["freshness.status"] = opts.Filter.Freshness
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
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
		sortBy = "occurredAt"
	}

	sortOrder := 1
	if !opts.SortAsc {
		sortOrder = -1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find findings by defcon: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored

	// Decode results
	findings := make([]*models.Finding, 0)

	for cursor.Next(ctx) {
		var finding models.Finding
		if err := cursor.Decode(&finding); err != nil {
			return nil, fmt.Errorf("failed to decode finding: %w", err)
		}

		findings = append(findings, &finding)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.FindingListResponse{
		Items:      findings,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetByFindingType returns findings of a specific type.
// Implements FindingStorer interface.
func (s *FindingStore) GetByFindingType(
	ctx context.Context,
	findingType models.FindingType,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting findings by findingType from store", "findingType", findingType)

	// Build filter
	filter := bson.M{"findingType": findingType}

	// Apply additional filters from opts
	if opts.Filter.AssetID != "" {
		filter["assetId"] = opts.Filter.AssetID
	}

	if opts.Filter.DefconID != "" {
		filter["defconId"] = opts.Filter.DefconID
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	if opts.Filter.Lifecycle != "" {
		filter["lifecycle.status"] = opts.Filter.Lifecycle
	}

	if opts.Filter.Verification != "" {
		filter["verification.status"] = opts.Filter.Verification
	}

	if opts.Filter.Freshness != "" {
		filter["freshness.status"] = opts.Filter.Freshness
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
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
		sortBy = "occurredAt"
	}

	sortOrder := 1
	if !opts.SortAsc {
		sortOrder = -1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find findings by type: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored

	// Decode results
	findings := make([]*models.Finding, 0)

	for cursor.Next(ctx) {
		var finding models.Finding
		if err := cursor.Decode(&finding); err != nil {
			return nil, fmt.Errorf("failed to decode finding: %w", err)
		}

		findings = append(findings, &finding)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.FindingListResponse{
		Items:      findings,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// GetStale returns findings that are stale.
// Implements FindingStorer interface.
func (s *FindingStore) GetStale(
	ctx context.Context,
	opts models.ListFindingsOptions,
) (*models.FindingListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting stale findings from store")

	// Build filter
	filter := bson.M{"freshness.status": models.FindingFreshnessStatusStale}

	// Apply additional filters from opts
	if opts.Filter.FindingType != "" {
		filter["findingType"] = opts.Filter.FindingType
	}

	if opts.Filter.AssetID != "" {
		filter["assetId"] = opts.Filter.AssetID
	}

	if opts.Filter.DefconID != "" {
		filter["defconId"] = opts.Filter.DefconID
	}

	if opts.Filter.Severity != "" {
		filter["severity"] = opts.Filter.Severity
	}

	if opts.Filter.Lifecycle != "" {
		filter["lifecycle.status"] = opts.Filter.Lifecycle
	}

	if opts.Filter.Verification != "" {
		filter["verification.status"] = opts.Filter.Verification
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
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
		sortBy = "occurredAt"
	}

	sortOrder := 1
	if !opts.SortAsc {
		sortOrder = -1
	}

	findOpts.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find stale findings: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored

	// Decode results
	findings := make([]*models.Finding, 0)

	for cursor.Next(ctx) {
		var finding models.Finding
		if err := cursor.Decode(&finding); err != nil {
			return nil, fmt.Errorf("failed to decode finding: %w", err)
		}

		findings = append(findings, &finding)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.FindingListResponse{
		Items:      findings,
		TotalCount: int(totalCount),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}, nil
}

// EnsureIndex creates the necessary indexes for the finding collection.
func (s *FindingStore) EnsureIndex(ctx context.Context) error {
	s.logger.V(vplogging.LogLevelInfo).Info("ensuring indexes for finding collection")

	// Create unique index on findingId
	findingIDIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "findingId", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	// Create index on findingType
	findingTypeIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "findingType", Value: 1}},
	}

	// Create index on sourceContext
	sourceContextIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "sourceContext", Value: 1}},
	}

	// Create index on assetId
	assetIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "assetId", Value: 1}},
	}

	// Create index on defconId
	defconIDIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "defconId", Value: 1}},
	}

	// Create index on severity
	severityIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "severity", Value: 1}},
	}

	// Create index on occurredAt for time-based queries
	occurredAtIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "occurredAt", Value: -1}},
	}

	// Create index on createdAt
	createdAtIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "createdAt", Value: -1}},
	}

	// Create index on lifecycle.status
	lifecycleStatusIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "lifecycle.status", Value: 1}},
	}

	// Create index on verification.status
	verificationStatusIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "verification.status", Value: 1}},
	}

	// Create index on freshness.status
	freshnessStatusIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "freshness.status", Value: 1}},
	}

	// Create compound index for common query patterns
	compoundQueryIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "assetId", Value: 1},
			{Key: "defconId", Value: 1},
			{Key: "findingType", Value: 1},
			{Key: "severity", Value: 1},
		},
	}

	// Create compound index for lifecycle queries
	compoundLifecycleIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "lifecycle.status", Value: 1},
			{Key: "occurredAt", Value: -1},
		},
	}

	// Create indexes
	_, err := s.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		findingIDIndex,
		findingTypeIndex,
		sourceContextIndex,
		assetIDIndex,
		defconIDIndex,
		severityIndex,
		occurredAtIndex,
		createdAtIndex,
		lifecycleStatusIndex,
		verificationStatusIndex,
		freshnessStatusIndex,
		compoundQueryIndex,
		compoundLifecycleIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}
