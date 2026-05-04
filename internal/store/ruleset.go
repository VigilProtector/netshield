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

// Errors for the ruleset store.
var (
	// ErrRuleSetNotFound is returned when a rule set is not found.
	ErrRuleSetNotFound = errors.New("rule set not found")
	// ErrRuleSetAlreadyExists is returned when a rule set already exists.
	ErrRuleSetAlreadyExists = errors.New("rule set already exists")
	// ErrRuleNotFound is returned when a rule is not found.
	ErrRuleNotFound = errors.New("rule not found")
	// ErrRuleAlreadyExists is returned when a rule already exists.
	ErrRuleAlreadyExists = errors.New("rule already exists")
)

// RuleSetStore implements RuleSetStorer interface for MongoDB persistence.
type RuleSetStore struct {
	collection *mongo.Collection
	logger     logr.Logger
}

// NewRuleSetStore creates a new RuleSetStore.
func NewRuleSetStore(collection *mongo.Collection, logger logr.Logger) *RuleSetStore {
	return &RuleSetStore{
		collection: collection,
		logger:     logger,
	}
}

// List returns a paginated list of rule sets with optional filtering.
// Implements RuleSetStorer interface.
func (s *RuleSetStore) List(
	ctx context.Context,
	opts models.RuleSetFilter,
) (*models.RuleSetListResponse, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("listing rule sets from store",
		"filter.name", opts.Name,
		"filter.version", opts.Version,
		"filter.source", opts.Source,
		"filter.enabled", opts.Enabled)

	// Build filter
	filter := bson.M{}

	if opts.Name != "" {
		filter["name"] = opts.Name
	}

	if opts.Version != "" {
		filter["version"] = opts.Version
	}

	if opts.Source != "" {
		filter["source"] = opts.Source
	}

	if opts.Enabled != nil {
		filter["enabled"] = *opts.Enabled
	}

	// Count total
	totalCount, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count rule sets: %w", err)
	}

	// Apply default sorting by name
	findOpts := options.Find().SetSort(bson.D{{Key: "name", Value: 1}})

	// Execute query
	cursor, err := s.collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find rule sets: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored

	// Decode results
	ruleSets := make([]*models.RuleSet, 0)

	for cursor.Next(ctx) {
		var ruleSet models.RuleSet
		if err := cursor.Decode(&ruleSet); err != nil {
			return nil, fmt.Errorf("failed to decode rule set: %w", err)
		}

		ruleSets = append(ruleSets, &ruleSet)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return &models.RuleSetListResponse{
		Items:      ruleSets,
		TotalCount: int(totalCount),
		Limit:      0, // Not paginated in this implementation
		Offset:     0,
	}, nil
}

// GetByID returns a single rule set by its ID.
// Implements RuleSetStorer interface.
func (s *RuleSetStore) GetByID(
	ctx context.Context,
	id string,
) (*models.RuleSet, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting rule set by id from store", "id", id)

	objID, err := bsonObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid id format: %w", err)
	}

	filter := bson.M{"_id": objID}

	var ruleSet models.RuleSet

	err = s.collection.FindOne(ctx, filter).Decode(&ruleSet)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get rule set by id: %w", err)
	}

	return &ruleSet, nil
}

// GetByName returns a single rule set by its name.
// Implements RuleSetStorer interface.
func (s *RuleSetStore) GetByName(
	ctx context.Context,
	name string,
) (*models.RuleSet, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting rule set by name from store", "name", name)

	filter := bson.M{"name": name}

	var ruleSet models.RuleSet

	err := s.collection.FindOne(ctx, filter).Decode(&ruleSet)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get rule set by name: %w", err)
	}

	return &ruleSet, nil
}

// GetDefault returns the default rule set (ET Open Baseline).
// Implements RuleSetStorer interface.
func (s *RuleSetStore) GetDefault(
	ctx context.Context,
) (*models.RuleSet, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting default rule set from store")

	filter := bson.M{
		"source":    models.RuleSetSourceETOpen,
		"isDefault": true,
	}

	var ruleSet models.RuleSet

	err := s.collection.FindOne(ctx, filter).Decode(&ruleSet)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get default rule set: %w", err)
	}

	return &ruleSet, nil
}

// Create creates a new rule set.
// Implements RuleSetStorer interface.
func (s *RuleSetStore) Create(
	ctx context.Context,
	ruleSet *models.RuleSet,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("creating rule set in store",
		"name", ruleSet.Name,
		"version", ruleSet.Version,
		"source", ruleSet.Source)

	// Insert rule set
	_, err := s.collection.InsertOne(ctx, ruleSet)
	if err != nil {
		// Check for duplicate key error
		var dupKeyErr mongo.WriteException
		if errors.As(err, &dupKeyErr) {
			for _, we := range dupKeyErr.WriteErrors {
				if we.Code == 11000 {
					return ErrRuleSetAlreadyExists
				}
			}
		}

		return fmt.Errorf("failed to create rule set: %w", err)
	}

	return nil
}

// Update updates an existing rule set.
// Implements RuleSetStorer interface.
func (s *RuleSetStore) Update(
	ctx context.Context,
	ruleSet *models.RuleSet,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("updating rule set in store",
		"id", ruleSet.ID.Hex(),
		"name", ruleSet.Name)

	// Build update
	filter := bson.M{"_id": ruleSet.ID}
	update := bson.M{
		"$set": bson.M{
			"name":        ruleSet.Name,
			"version":     ruleSet.Version,
			"description": ruleSet.Description,
			"enabled":     ruleSet.Enabled,
			"source":      ruleSet.Source,
			"rules":       ruleSet.Rules,
			"scope":       ruleSet.Scope,
			"isDefault":   ruleSet.IsDefault,
			"updatedAt":   ruleSet.UpdatedAt,
			"updatedBy":   ruleSet.UpdatedBy,
		},
	}

	// Execute update
	result, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update rule set: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrRuleSetNotFound
	}

	return nil
}

// Delete deletes a rule set by its ID.
// Implements RuleSetStorer interface.
func (s *RuleSetStore) Delete(
	ctx context.Context,
	id string,
) error {
	s.logger.V(vplogging.LogLevelVerbose).Info("deleting rule set from store", "id", id)

	objID, err := bsonObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("invalid id format: %w", err)
	}

	filter := bson.M{"_id": objID}

	result, err := s.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete rule set: %w", err)
	}

	if result.DeletedCount == 0 {
		return ErrRuleSetNotFound
	}

	return nil
}

// GetByScope returns rule sets that apply to a specific scope.
// Implements RuleSetStorer interface.
func (s *RuleSetStore) GetByScope(
	ctx context.Context,
	scopeType models.ScopeType,
	defconID, namespace string,
) ([]*models.RuleSet, error) {
	s.logger.V(vplogging.LogLevelVerbose).Info("getting rule sets by scope from store",
		"scopeType", scopeType,
		"defconId", defconID,
		"namespace", namespace)

	// Build filter based on scope type
	filter := bson.M{}

	switch scopeType {
	case models.ScopeTypeGlobal:
		// Global rule sets apply to all scopes
		filter["scope.type"] = models.ScopeTypeGlobal
	case models.ScopeTypeDefconSpecific:
		// Defcon-specific rule sets
		filter["$or"] = bson.A{
			bson.M{"scope.type": models.ScopeTypeGlobal},
			bson.M{
				"scope.type":      models.ScopeTypeDefconSpecific,
				"scope.defconIds": bson.M{"$in": []string{defconID}},
			},
		}
	case models.ScopeTypeNamespaceSpecific:
		// Namespace-specific rule sets
		filter["$or"] = bson.A{
			bson.M{"scope.type": models.ScopeTypeGlobal},
			bson.M{
				"scope.type":      models.ScopeTypeDefconSpecific,
				"scope.defconIds": bson.M{"$in": []string{defconID}},
			},
			bson.M{
				"scope.type":      models.ScopeTypeNamespaceSpecific,
				"scope.namespace": namespace,
			},
		}
	}

	// Only get enabled rule sets
	filter["enabled"] = true

	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find rule sets by scope: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored

	ruleSets := make([]*models.RuleSet, 0)

	for cursor.Next(ctx) {
		var ruleSet models.RuleSet
		if err := cursor.Decode(&ruleSet); err != nil {
			return nil, fmt.Errorf("failed to decode rule set: %w", err)
		}

		ruleSets = append(ruleSets, &ruleSet)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return ruleSets, nil
}

// EnsureIndex creates the necessary indexes for the ruleset collection.
func (s *RuleSetStore) EnsureIndex(ctx context.Context) error {
	s.logger.V(vplogging.LogLevelInfo).Info("ensuring indexes for ruleset collection")

	// Create unique index on name
	nameIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	// Create index on source
	sourceIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "source", Value: 1}},
	}

	// Create index on enabled
	enabledIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "enabled", Value: 1}},
	}

	// Create index on isDefault
	isDefaultIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "isDefault", Value: 1}},
	}

	// Create compound index on source + isDefault for default queries
	compoundDefaultIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "source", Value: 1},
			{Key: "isDefault", Value: 1},
		},
	}

	// Create index on scope.type
	scopeTypeIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "scope.type", Value: 1}},
	}

	// Create index on scope.defconIds for defcon-specific lookups
	defconIDsIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "scope.defconIds", Value: 1}},
	}

	// Create index on scope.namespace for namespace-specific lookups
	namespaceIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "scope.namespace", Value: 1}},
	}

	// Create indexes
	_, err := s.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		nameIndex,
		sourceIndex,
		enabledIndex,
		isDefaultIndex,
		compoundDefaultIndex,
		scopeTypeIndex,
		defconIDsIndex,
		namespaceIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}
