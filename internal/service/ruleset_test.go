// Package service_test contains unit tests for the service layer.
package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/vp-lib/types"
)

// mockRuleSetStore implements service.RuleSetStorer interface for testing.
type mockRuleSetStore struct {
	listFunc          func(ctx context.Context, opts models.RuleSetFilter) (*models.RuleSetListResponse, error)
	getByIDFunc       func(ctx context.Context, id string) (*models.RuleSet, error)
	getByNameFunc     func(ctx context.Context, name string) (*models.RuleSet, error)
	getDefaultFunc    func(ctx context.Context) (*models.RuleSet, error)
	createFunc        func(ctx context.Context, ruleset *models.RuleSet) error
	updateFunc        func(ctx context.Context, ruleset *models.RuleSet) error
	deleteFunc        func(ctx context.Context, id string) error
	getByScopeFunc    func(ctx context.Context, scopeType models.ScopeType, defconID, namespace string) ([]*models.RuleSet, error)
}

func (m *mockRuleSetStore) List(ctx context.Context, opts models.RuleSetFilter) (*models.RuleSetListResponse, error) {
	return m.listFunc(ctx, opts)
}

func (m *mockRuleSetStore) GetByID(ctx context.Context, id string) (*models.RuleSet, error) {
	return m.getByIDFunc(ctx, id)
}

func (m *mockRuleSetStore) GetByName(ctx context.Context, name string) (*models.RuleSet, error) {
	return m.getByNameFunc(ctx, name)
}

func (m *mockRuleSetStore) GetDefault(ctx context.Context) (*models.RuleSet, error) {
	return m.getDefaultFunc(ctx)
}

func (m *mockRuleSetStore) Create(ctx context.Context, ruleset *models.RuleSet) error {
	return m.createFunc(ctx, ruleset)
}

func (m *mockRuleSetStore) Update(ctx context.Context, ruleset *models.RuleSet) error {
	return m.updateFunc(ctx, ruleset)
}

func (m *mockRuleSetStore) Delete(ctx context.Context, id string) error {
	return m.deleteFunc(ctx, id)
}

func (m *mockRuleSetStore) GetByScope(ctx context.Context, scopeType models.ScopeType, defconID, namespace string) ([]*models.RuleSet, error) {
	return m.getByScopeFunc(ctx, scopeType, defconID, namespace)
}

// mockRuleStore implements service.RuleStorer interface for testing.
type mockRuleStore struct {
	listFunc        func(ctx context.Context, opts models.ListRulesOptions) (*models.RuleListResponse, error)
	getByIDFunc     func(ctx context.Context, id string) (*models.Rule, error)
	getByRuleIDFunc func(ctx context.Context, ruleID string) (*models.Rule, error)
	createFunc      func(ctx context.Context, rule *models.Rule) error
	updateFunc      func(ctx context.Context, rule *models.Rule) error
	deleteFunc      func(ctx context.Context, id string) error
	getByRuleIDsFunc func(ctx context.Context, ruleIDs []string) ([]*models.Rule, error)
}

func (m *mockRuleStore) List(ctx context.Context, opts models.ListRulesOptions) (*models.RuleListResponse, error) {
	return m.listFunc(ctx, opts)
}

func (m *mockRuleStore) GetByID(ctx context.Context, id string) (*models.Rule, error) {
	return m.getByIDFunc(ctx, id)
}

func (m *mockRuleStore) GetByRuleID(ctx context.Context, ruleID string) (*models.Rule, error) {
	return m.getByRuleIDFunc(ctx, ruleID)
}

func (m *mockRuleStore) Create(ctx context.Context, rule *models.Rule) error {
	return m.createFunc(ctx, rule)
}

func (m *mockRuleStore) Update(ctx context.Context, rule *models.Rule) error {
	return m.updateFunc(ctx, rule)
}

func (m *mockRuleStore) Delete(ctx context.Context, id string) error {
	return m.deleteFunc(ctx, id)
}

func (m *mockRuleStore) GetByRuleIDs(ctx context.Context, ruleIDs []string) ([]*models.Rule, error) {
	return m.getByRuleIDsFunc(ctx, ruleIDs)
}

func TestRuleSetService_List(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testRuleSets := []*models.RuleSet{
		{
			Name:    "ET Open Baseline",
			Version: "1.0.0",
			Source:  models.RuleSetSourceETOpen,
			Enabled: true,
			Scope: models.RuleSetScope{
				Type: "global",
			},
			IsDefault: true,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		},
		{
			Name:    "Custom Rules",
			Version: "1.0.0",
			Source:  models.RuleSetSourceCustom,
			Enabled: false,
			Scope: models.RuleSetScope{
				Type:      "defcon-specific",
				DefconIDs: []string{"defcon-1"},
			},
			IsDefault: false,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		},
	}

	testCases := []struct {
		name           string
		filter         models.RuleSetFilter
		storeList      *models.RuleSetListResponse
		storeListErr   error
		expectedCount  int
		expectedError  bool
	}{
		{
			name:   "successful list with no filter",
			filter: models.RuleSetFilter{},
			storeList: &models.RuleSetListResponse{
				Items:      testRuleSets,
				TotalCount: 2,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 2,
			expectedError: false,
		},
		{
			name:   "successful list with name filter",
			filter: models.RuleSetFilter{Name: "ET Open Baseline"},
			storeList: &models.RuleSetListResponse{
				Items:      testRuleSets[:1],
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:   "successful list with source filter",
			filter: models.RuleSetFilter{Source: string(models.RuleSetSourceETOpen)},
			storeList: &models.RuleSetListResponse{
				Items:      testRuleSets[:1],
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:         "store error",
			filter:       models.RuleSetFilter{},
			storeList:    nil,
			storeListErr: errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				listFunc: func(ctx context.Context, opts models.RuleSetFilter) (*models.RuleSetListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.List(ctx, logger, subject, tc.filter)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to list rule sets from store")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestRuleSetService_Get(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testRuleSet := &models.RuleSet{
		Name:    "ET Open Baseline",
		Version: "1.0.0",
		Source:  models.RuleSetSourceETOpen,
		Enabled: true,
		Scope: models.RuleSetScope{
			Type: "global",
		},
		IsDefault: true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}

	testCases := []struct {
		name         string
		id           string
		storeRuleSet *models.RuleSet
		storeErr    error
		expectedNil  bool
		expectedError bool
	}{
		{
			name:         "successful get",
			id:           "rule-set-1",
			storeRuleSet: testRuleSet,
			storeErr:     nil,
			expectedNil:  false,
			expectedError: false,
		},
		{
			name:         "rule set not found",
			id:           "rule-set-1",
			storeRuleSet: nil,
			storeErr:     nil,
			expectedNil:  true,
			expectedError: true,
		},
		{
			name:         "store error",
			id:           "rule-set-1",
			storeRuleSet: nil,
			storeErr:     errors.New("store error"),
			expectedNil:  true,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getByIDFunc: func(ctx context.Context, id string) (*models.RuleSet, error) {
					return tc.storeRuleSet, tc.storeErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.Get(ctx, logger, subject, tc.id)

			if tc.expectedError {
				require.Error(t, err)
				if tc.storeErr != nil {
					assert.Contains(t, err.Error(), "failed to get rule set from store")
				} else {
					// When store returns nil with no error, service returns ErrRuleSetNotFound
					assert.Equal(t, service.ErrRuleSetNotFound, err)
				}
			} else {
				require.NoError(t, err)
			}

			if tc.expectedNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tc.storeRuleSet.Name, result.Name)
			}
		})
	}
}

func TestRuleSetService_Create(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testCases := []struct {
		name           string
		req            models.CreateRuleSetRequest
		storeGetByName *models.RuleSet
		storeGetByNameErr error
		storeGetDefault *models.RuleSet
		storeGetDefaultErr error
		storeCreateErr error
		expectedError  bool
		expectDefault  bool
	}{
		{
			name: "successful create - ET Open with no existing default",
			req: models.CreateRuleSetRequest{
				Name:        "ET Open Baseline",
				Version:     "1.0.0",
				Description: "Emerging Threats Open rules",
				Enabled:     true,
				Source:      string(models.RuleSetSourceETOpen),
				Rules: []models.RuleRefAPI{
					{RuleID: "2001234", Enabled: true},
				},
				Scope: models.ScopeAPI{
					Type: "global",
				},
			},
			storeGetByName:    nil,
			storeGetByNameErr: nil,
			storeGetDefault:   nil,
			storeGetDefaultErr: nil,
			storeCreateErr:    nil,
			expectedError:     false,
			expectDefault:     true,
		},
		{
			name: "successful create - ET Open with existing default",
			req: models.CreateRuleSetRequest{
				Name:        "ET Open New",
				Version:     "2.0.0",
				Description: "Emerging Threats Open rules v2",
				Enabled:     true,
				Source:      string(models.RuleSetSourceETOpen),
				Rules: []models.RuleRefAPI{
					{RuleID: "2001234", Enabled: true},
				},
				Scope: models.ScopeAPI{
					Type: "global",
				},
			},
			storeGetByName:    nil,
			storeGetByNameErr: nil,
			storeGetDefault: &models.RuleSet{
				Name:   "Existing Default",
				Source: models.RuleSetSourceETOpen,
			},
			storeGetDefaultErr: nil,
			storeCreateErr:    nil,
			expectedError:     false,
			expectDefault:     false,
		},
		{
			name: "successful create - custom ruleset",
			req: models.CreateRuleSetRequest{
				Name:        "Custom Rules",
				Version:     "1.0.0",
				Description: "Custom detection rules",
				Enabled:     false,
				Source:      string(models.RuleSetSourceCustom),
				Rules: []models.RuleRefAPI{
					{RuleID: "1000001", Enabled: true},
				},
				Scope: models.ScopeAPI{
					Type:      "defcon-specific",
					DefconIDs: []string{"defcon-1"},
				},
			},
			storeGetByName:    nil,
			storeGetByNameErr: nil,
			storeGetDefault:   nil,
			storeGetDefaultErr: nil,
			storeCreateErr:    nil,
			expectedError:     false,
			expectDefault:     false,
		},
		{
			name: "error - missing name",
			req: models.CreateRuleSetRequest{
				Version: "1.0.0",
				Source:  string(models.RuleSetSourceETOpen),
			},
			storeGetByName:    nil,
			storeGetByNameErr: nil,
			storeGetDefault:   nil,
			storeGetDefaultErr: nil,
			storeCreateErr:    nil,
			expectedError:     true,
			expectDefault:     false,
		},
		{
			name: "error - invalid source",
			req: models.CreateRuleSetRequest{
				Name:   "Invalid Source",
				Source: "invalid-source",
			},
			storeGetByName:    nil,
			storeGetByNameErr: nil,
			storeGetDefault:   nil,
			storeGetDefaultErr: nil,
			storeCreateErr:    nil,
			expectedError:     true,
			expectDefault:     false,
		},
		{
			name: "error - already exists",
			req: models.CreateRuleSetRequest{
				Name:   "Existing",
				Source: string(models.RuleSetSourceETOpen),
			},
			storeGetByName: &models.RuleSet{
				Name: "Existing",
			},
			storeGetByNameErr: nil,
			storeGetDefault:   nil,
			storeGetDefaultErr: nil,
			storeCreateErr:    nil,
			expectedError:     true,
			expectDefault:     false,
		},
		{
			name: "error - store get by name error",
			req: models.CreateRuleSetRequest{
				Name:   "New",
				Source: string(models.RuleSetSourceETOpen),
			},
			storeGetByName:    nil,
			storeGetByNameErr: errors.New("store error"),
			storeGetDefault:   nil,
			storeGetDefaultErr: nil,
			storeCreateErr:    nil,
			expectedError:     true,
			expectDefault:     false,
		},
		{
			name: "error - store create error",
			req: models.CreateRuleSetRequest{
				Name:   "New",
				Source: string(models.RuleSetSourceETOpen),
			},
			storeGetByName:    nil,
			storeGetByNameErr: nil,
			storeGetDefault:   nil,
			storeGetDefaultErr: nil,
			storeCreateErr:    errors.New("create error"),
			expectedError:     true,
			expectDefault:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getByNameFunc: func(ctx context.Context, name string) (*models.RuleSet, error) {
					return tc.storeGetByName, tc.storeGetByNameErr
				},
				getDefaultFunc: func(ctx context.Context) (*models.RuleSet, error) {
					return tc.storeGetDefault, tc.storeGetDefaultErr
				},
				createFunc: func(ctx context.Context, ruleset *models.RuleSet) error {
					return tc.storeCreateErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.Create(ctx, logger, subject, tc.req)

			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.req.Name, result.Name)
			assert.Equal(t, tc.req.Version, result.Version)
			assert.Equal(t, models.RuleSetSource(tc.req.Source), result.Source)
			assert.Equal(t, tc.expectDefault, result.IsDefault)
			assert.Equal(t, subject.ID, result.CreatedBy)
			assert.Equal(t, subject.ID, result.UpdatedBy)
		})
	}
}

func TestRuleSetService_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	// Helper to create a fresh copy of existing rule set for each test case
	newExistingRuleSet := func() *models.RuleSet {
		return &models.RuleSet{
			Name:    "Existing Rules",
			Version: "1.0.0",
			Source:  models.RuleSetSourceCustom,
			Enabled: true,
			Scope: models.RuleSetScope{
				Type:      "defcon-specific",
				DefconIDs: []string{"defcon-1"},
			},
			Rules: []models.RuleRef{
				{RuleID: "1000001", Enabled: true},
			},
			IsDefault: false,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		}
	}

	testCases := []struct {
		name          string
		id            string
		req           models.UpdateRuleSetRequest
		storeRuleSet  *models.RuleSet
		storeRuleSetErr error
		storeUpdateErr error
		expectedError bool
		expectName    string
		expectVersion string
		expectEnabled bool
	}{
		{
			name:         "successful update - all fields",
			id:           "rule-set-1",
			req: models.UpdateRuleSetRequest{
				Name:        "Updated Rules",
				Version:     "2.0.0",
				Description: "Updated description",
				Enabled:     boolPtr(false),
				Rules: []models.RuleRefAPI{
					{RuleID: "1000002", Enabled: true},
				},
				Scope: models.ScopeAPI{
					Type:      "namespace-specific",
					Namespace: "production",
				},
			},
			storeRuleSet:    newExistingRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:   nil,
			expectedError:   false,
			expectName:      "Updated Rules",
			expectVersion:   "2.0.0",
			expectEnabled:   false,
		},
		{
			name:         "successful update - partial fields",
			id:           "rule-set-1",
			req: models.UpdateRuleSetRequest{
				Version: "2.0.0",
			},
			storeRuleSet:    newExistingRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:   nil,
			expectedError:   false,
			expectName:      "Existing Rules",
			expectVersion:   "2.0.0",
			expectEnabled:   true,
		},
		{
			name:         "error - rule set not found",
			id:           "rule-set-1",
			req:           models.UpdateRuleSetRequest{},
			storeRuleSet:    nil,
			storeRuleSetErr: nil,
			storeUpdateErr:   nil,
			expectedError:   true,
		},
		{
			name:         "error - store get error",
			id:           "rule-set-1",
			req:           models.UpdateRuleSetRequest{},
			storeRuleSet:    nil,
			storeRuleSetErr: errors.New("get error"),
			storeUpdateErr:   nil,
			expectedError:   true,
		},
		{
			name:         "error - store update error",
			id:           "rule-set-1",
			req:           models.UpdateRuleSetRequest{},
			storeRuleSet:    newExistingRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:   errors.New("update error"),
			expectedError:   true,
		},
		{
			name:         "error - invalid source",
			id:           "rule-set-1",
			req: models.UpdateRuleSetRequest{
				Source: "invalid-source",
			},
			storeRuleSet:    newExistingRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:   nil,
			expectedError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getByIDFunc: func(ctx context.Context, id string) (*models.RuleSet, error) {
					return tc.storeRuleSet, tc.storeRuleSetErr
				},
				updateFunc: func(ctx context.Context, ruleset *models.RuleSet) error {
					return tc.storeUpdateErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.Update(ctx, logger, subject, tc.id, tc.req)

			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.expectName, result.Name)
			assert.Equal(t, tc.expectVersion, result.Version)
			assert.Equal(t, tc.expectEnabled, result.Enabled)
			assert.Equal(t, subject.ID, result.UpdatedBy)
		})
	}
}

func TestRuleSetService_Delete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	defaultRuleSet := &models.RuleSet{
		Name:    "ET Open Baseline",
		Source:  models.RuleSetSourceETOpen,
		IsDefault: true,
	}

	nonDefaultRuleSet := &models.RuleSet{
		Name:    "Custom Rules",
		Source:  models.RuleSetSourceCustom,
		IsDefault: false,
	}

	testCases := []struct {
		name          string
		id            string
		storeRuleSet  *models.RuleSet
		storeRuleSetErr error
		storeDeleteErr error
		expectedError bool
	}{
		{
			name:         "successful delete - non-default",
			id:           "rule-set-1",
			storeRuleSet: nonDefaultRuleSet,
			storeRuleSetErr: nil,
			storeDeleteErr:  nil,
			expectedError:  false,
		},
		{
			name:         "error - delete default rule set",
			id:           "rule-set-1",
			storeRuleSet: defaultRuleSet,
			storeRuleSetErr: nil,
			storeDeleteErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - rule set not found",
			id:           "rule-set-1",
			storeRuleSet: nil,
			storeRuleSetErr: nil,
			storeDeleteErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - store get error",
			id:           "rule-set-1",
			storeRuleSet:    nil,
			storeRuleSetErr: errors.New("get error"),
			storeDeleteErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - store delete error",
			id:           "rule-set-1",
			storeRuleSet: nonDefaultRuleSet,
			storeRuleSetErr: nil,
			storeDeleteErr:  errors.New("delete error"),
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getByIDFunc: func(ctx context.Context, id string) (*models.RuleSet, error) {
					return tc.storeRuleSet, tc.storeRuleSetErr
				},
				deleteFunc: func(ctx context.Context, id string) error {
					return tc.storeDeleteErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			err := svc.Delete(ctx, logger, subject, tc.id)

			if tc.expectedError {
				require.Error(t, err)
				if tc.name == "error - delete default rule set" {
					assert.Equal(t, service.ErrDefaultRuleSetCannotDelete, err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRuleSetService_Enable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	// Helper to create a fresh disabled rule set for each test case
	newDisabledRuleSet := func() *models.RuleSet {
		return &models.RuleSet{
			Name:    "Custom Rules",
			Enabled: false,
			Source:  models.RuleSetSourceCustom,
			IsDefault: false,
		}
	}

	// Helper to create a fresh enabled rule set for each test case
	newEnabledRuleSet := func() *models.RuleSet {
		return &models.RuleSet{
			Name:    "Custom Rules",
			Enabled: true,
			Source:  models.RuleSetSourceCustom,
			IsDefault: false,
		}
	}

	testCases := []struct {
		name          string
		id            string
		storeRuleSet  *models.RuleSet
		storeRuleSetErr error
		storeUpdateErr error
		expectedError bool
		expectEnabled bool
	}{
		{
			name:         "successful enable",
			id:           "rule-set-1",
			storeRuleSet: newDisabledRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:  nil,
			expectedError:  false,
			expectEnabled:  true,
		},
		{
			name:         "already enabled",
			id:           "rule-set-1",
			storeRuleSet: newEnabledRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:  nil,
			expectedError:  false,
			expectEnabled:  true,
		},
		{
			name:         "error - rule set not found",
			id:           "rule-set-1",
			storeRuleSet: nil,
			storeRuleSetErr: nil,
			storeUpdateErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - store get error",
			id:           "rule-set-1",
			storeRuleSet:    nil,
			storeRuleSetErr: errors.New("get error"),
			storeUpdateErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - store update error",
			id:           "rule-set-1",
			storeRuleSet: newDisabledRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:  errors.New("update error"),
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getByIDFunc: func(ctx context.Context, id string) (*models.RuleSet, error) {
					return tc.storeRuleSet, tc.storeRuleSetErr
				},
				updateFunc: func(ctx context.Context, ruleset *models.RuleSet) error {
					return tc.storeUpdateErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.Enable(ctx, logger, subject, tc.id)

			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.expectEnabled, result.Enabled)
		})
	}
}

func TestRuleSetService_Disable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	// Helper to create a fresh enabled rule set for each test case
	newEnabledRuleSet := func() *models.RuleSet {
		return &models.RuleSet{
			Name:    "Custom Rules",
			Enabled: true,
			Source:  models.RuleSetSourceCustom,
			IsDefault: false,
		}
	}

	// Helper to create a fresh disabled rule set for each test case
	newDisabledRuleSet := func() *models.RuleSet {
		return &models.RuleSet{
			Name:    "Custom Rules",
			Enabled: false,
			Source:  models.RuleSetSourceCustom,
			IsDefault: false,
		}
	}

	// Helper to create a fresh default rule set for each test case
	newDefaultRuleSet := func() *models.RuleSet {
		return &models.RuleSet{
			Name:    "ET Open Baseline",
			Enabled: true,
			Source:  models.RuleSetSourceETOpen,
			IsDefault: true,
		}
	}

	testCases := []struct {
		name          string
		id            string
		storeRuleSet  *models.RuleSet
		storeRuleSetErr error
		storeUpdateErr error
		expectedError bool
		expectEnabled bool
	}{
		{
			name:         "successful disable",
			id:           "rule-set-1",
			storeRuleSet: newEnabledRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:  nil,
			expectedError:  false,
			expectEnabled:  false,
		},
		{
			name:         "already disabled",
			id:           "rule-set-1",
			storeRuleSet: newDisabledRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:  nil,
			expectedError:  false,
			expectEnabled:  false,
		},
		{
			name:         "error - disable default rule set",
			id:           "rule-set-1",
			storeRuleSet: newDefaultRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - rule set not found",
			id:           "rule-set-1",
			storeRuleSet: nil,
			storeRuleSetErr: nil,
			storeUpdateErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - store get error",
			id:           "rule-set-1",
			storeRuleSet:    nil,
			storeRuleSetErr: errors.New("get error"),
			storeUpdateErr:  nil,
			expectedError:  true,
		},
		{
			name:         "error - store update error",
			id:           "rule-set-1",
			storeRuleSet: newEnabledRuleSet(),
			storeRuleSetErr: nil,
			storeUpdateErr:  errors.New("update error"),
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getByIDFunc: func(ctx context.Context, id string) (*models.RuleSet, error) {
					return tc.storeRuleSet, tc.storeRuleSetErr
				},
				updateFunc: func(ctx context.Context, ruleset *models.RuleSet) error {
					return tc.storeUpdateErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.Disable(ctx, logger, subject, tc.id)

			if tc.expectedError {
				require.Error(t, err)
				if tc.name == "error - disable default rule set" {
					assert.Equal(t, service.ErrDefaultRuleSetCannotDisable, err)
				}
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.expectEnabled, result.Enabled)
		})
	}
}

func TestRuleSetService_GetDefault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	defaultRuleSet := &models.RuleSet{
		Name:    "ET Open Baseline",
		Version: "1.0.0",
		Source:  models.RuleSetSourceETOpen,
		Enabled: true,
		Scope: models.RuleSetScope{
			Type: "global",
		},
		IsDefault: true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		CreatedBy: "system",
		UpdatedBy: "system",
	}

	testCases := []struct {
		name          string
		storeDefault  *models.RuleSet
		storeErr     error
		expectedNil   bool
		expectedError bool
	}{
		{
			name:         "successful get default",
			storeDefault: defaultRuleSet,
			storeErr:     nil,
			expectedNil:   false,
			expectedError: false,
		},
		{
			name:         "default not found",
			storeDefault: nil,
			storeErr:     nil,
			expectedNil:   true,
			expectedError: true,
		},
		{
			name:         "store error",
			storeDefault: nil,
			storeErr:     errors.New("store error"),
			expectedNil:   true,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getDefaultFunc: func(ctx context.Context) (*models.RuleSet, error) {
					return tc.storeDefault, tc.storeErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.GetDefault(ctx, logger, subject)

			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tc.expectedNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tc.storeDefault.Name, result.Name)
				assert.True(t, result.IsDefault)
			}
		})
	}
}

func TestRuleSetService_Render(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	ruleSet := &models.RuleSet{
		Name:    "ET Open Baseline",
		Version: "1.0.0",
		Source:  models.RuleSetSourceETOpen,
		Rules: []models.RuleRef{
			{RuleID: "2001234", Enabled: true},
			{RuleID: "2005678", Enabled: false}, // Disabled, should not be rendered
		},
	}

	rules := []*models.Rule{
		{
			RuleID:  "2001234",
			Content: "alert tcp any any -> any any (msg:\"Test Rule\"; sid:2001234; rev:1;)",
			Default: true,
		},
		{
			RuleID:  "2005678",
			Content: "alert tcp any any -> any any (msg:\"Disabled Rule\"; sid:2005678; rev:1;)",
			Default: false,
		},
	}

	testCases := []struct {
		name          string
		id            string
		storeRuleSet  *models.RuleSet
		storeRuleSetErr error
		storeRules    []*models.Rule
		storeRulesErr error
		expectedError bool
		expectOutput  bool
	}{
		{
			name:         "successful render with enabled rules",
			id:           "rule-set-1",
			storeRuleSet: ruleSet,
			storeRuleSetErr: nil,
			storeRules:    rules,
			storeRulesErr: nil,
			expectedError: false,
			expectOutput:  true,
		},
		{
			name:         "error - rule set not found",
			id:           "rule-set-1",
			storeRuleSet: nil,
			storeRuleSetErr: nil,
			storeRules:    nil,
			storeRulesErr: nil,
			expectedError: true,
			expectOutput:  false,
		},
		{
			name:         "error - store get rule set error",
			id:           "rule-set-1",
			storeRuleSet:    nil,
			storeRuleSetErr: errors.New("get error"),
			storeRules:    nil,
			storeRulesErr: nil,
			expectedError: true,
			expectOutput:  false,
		},
		{
			name:         "error - store get rules error",
			id:           "rule-set-1",
			storeRuleSet: ruleSet,
			storeRuleSetErr: nil,
			storeRules:    nil,
			storeRulesErr: errors.New("get rules error"),
			expectedError: true,
			expectOutput:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ruleStore := &mockRuleStore{
				getByRuleIDsFunc: func(ctx context.Context, ruleIDs []string) ([]*models.Rule, error) {
					return tc.storeRules, tc.storeRulesErr
				},
			}

			store := &mockRuleSetStore{
				getByIDFunc: func(ctx context.Context, id string) (*models.RuleSet, error) {
					return tc.storeRuleSet, tc.storeRuleSetErr
				},
			}

			svc := service.NewRuleSetService(store, ruleStore, logger)

			result, err := svc.Render(ctx, logger, subject, tc.id)

			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tc.expectOutput {
				assert.NotEmpty(t, result)
				assert.Contains(t, result, "# Rule Set: ET Open Baseline")
				assert.Contains(t, result, "# Version: 1.0.0")
				assert.Contains(t, result, "# Source: et-open")
				assert.Contains(t, result, "msg:\"Test Rule\"")
				assert.NotContains(t, result, "Disabled Rule")
			}
		})
	}
}

func TestRuleSetService_GetRuleSetsByScope(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testRuleSets := []*models.RuleSet{
		{
			Name: "Global Rules",
			Scope: models.RuleSetScope{
				Type: "global",
			},
		},
		{
			Name: "Defcon Specific Rules",
			Scope: models.RuleSetScope{
				Type:      "defcon-specific",
				DefconIDs: []string{"defcon-1"},
			},
		},
	}

	testCases := []struct {
		name           string
		scopeType      models.ScopeType
		defconID       string
		namespace      string
		storeRuleSets  []*models.RuleSet
		storeErr       error
		expectedCount  int
		expectedError  bool
	}{
		{
			name:          "successful get by global scope",
			scopeType:     models.ScopeTypeGlobal,
			defconID:      "",
			namespace:     "",
			storeRuleSets: testRuleSets[:1],
			storeErr:      nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "successful get by defcon scope",
			scopeType:     models.ScopeTypeDefconSpecific,
			defconID:      "defcon-1",
			namespace:     "",
			storeRuleSets: testRuleSets[1:],
			storeErr:      nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "error - store error",
			scopeType:     models.ScopeTypeGlobal,
			defconID:      "",
			namespace:     "",
			storeRuleSets: nil,
			storeErr:      errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockRuleSetStore{
				getByScopeFunc: func(ctx context.Context, scopeType models.ScopeType, defconID, namespace string) ([]*models.RuleSet, error) {
					return tc.storeRuleSets, tc.storeErr
				},
			}

			svc := service.NewRuleSetService(store, nil, logger)

			result, err := svc.GetRuleSetsByScope(ctx, logger, subject, tc.scopeType, tc.defconID, tc.namespace)

			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, result, tc.expectedCount)
		})
	}
}

// Helper functions

func boolPtr(b bool) *bool {
	return &b
}
