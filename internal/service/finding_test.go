// Package service_test contains unit tests for the service layer.
package service_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/vp-lib/types"
)

// mockFindingStore implements service.FindingStorer interface for testing.
type mockFindingStore struct {
	listFunc             func(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	getByIDFunc          func(ctx context.Context, findingID string) (*models.Finding, error)
	getByFindingIDFunc   func(ctx context.Context, findingID string) (*models.Finding, error)
	createFunc           func(ctx context.Context, finding *models.Finding) error
	updateFunc           func(ctx context.Context, finding *models.Finding) error
	deleteFunc           func(ctx context.Context, id string) error
	getByAssetIDFunc     func(ctx context.Context, assetID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	getByDefconIDFunc    func(ctx context.Context, defconID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	getByFindingTypeFunc func(ctx context.Context, findingType models.FindingType, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
	getStaleFunc         func(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error)
}

func (m *mockFindingStore) List(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return m.listFunc(ctx, opts)
}

func (m *mockFindingStore) GetByID(ctx context.Context, findingID string) (*models.Finding, error) {
	return m.getByIDFunc(ctx, findingID)
}

func (m *mockFindingStore) GetByFindingID(ctx context.Context, findingID string) (*models.Finding, error) {
	return m.getByFindingIDFunc(ctx, findingID)
}

func (m *mockFindingStore) Create(ctx context.Context, finding *models.Finding) error {
	return m.createFunc(ctx, finding)
}

func (m *mockFindingStore) Update(ctx context.Context, finding *models.Finding) error {
	return m.updateFunc(ctx, finding)
}

func (m *mockFindingStore) Delete(ctx context.Context, id string) error {
	return m.deleteFunc(ctx, id)
}

func (m *mockFindingStore) GetByAssetID(ctx context.Context, assetID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return m.getByAssetIDFunc(ctx, assetID, opts)
}

func (m *mockFindingStore) GetByDefconID(ctx context.Context, defconID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return m.getByDefconIDFunc(ctx, defconID, opts)
}

func (m *mockFindingStore) GetByFindingType(ctx context.Context, findingType models.FindingType, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return m.getByFindingTypeFunc(ctx, findingType, opts)
}

func (m *mockFindingStore) GetStale(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return m.getStaleFunc(ctx, opts)
}

// Helper to create a test finding
func newTestFinding(findingID string) *models.Finding {
	now := time.Now().UTC()
	return &models.Finding{
		FindingID:    findingID,
		FindingType:  models.FindingTypeKnownAttackPatternDetected,
		Severity:     models.FindingSeverityHigh,
		AssetID:      "asset-1",
		DefconID:     "defcon-1",
		Title:        "Test Finding",
		Description:  "Test description",
		OccurredAt:   now,
		Confidence:   0.95,
		Lifecycle:    models.FindingLifecycle{Status: models.FindingLifecycleStatusOpen},
		Verification: models.FindingVerification{Status: models.FindingVerificationStatusUnverified},
		Freshness:    models.FindingFreshness{Status: models.FindingFreshnessStatusFresh},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestFindingService_List(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testFindings := []*models.Finding{
		newTestFinding("finding-1"),
		newTestFinding("finding-2"),
	}

	testCases := []struct {
		name          string
		opts          models.ListFindingsOptions
		storeList     *models.FindingListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name: "successful list with no filter",
			opts: models.ListFindingsOptions{},
			storeList: &models.FindingListResponse{
				Items:      testFindings,
				TotalCount: 2,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 2,
			expectedError: false,
		},
		{
			name: "successful list with asset filter",
			opts: models.ListFindingsOptions{Filter: models.FindingFilter{AssetID: "asset-1"}},
			storeList: &models.FindingListResponse{
				Items:      testFindings[:1],
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "store error",
			opts:          models.ListFindingsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				listFunc: func(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.List(ctx, logger, subject, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to list findings from store")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestFindingService_Get(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testFinding := newTestFinding("finding-1")

	testCases := []struct {
		name          string
		findingID     string
		storeFinding  *models.Finding
		storeErr      error
		expectedNil   bool
		expectedError bool
	}{
		{
			name:          "successful get",
			findingID:     "finding-1",
			storeFinding:  testFinding,
			storeErr:      nil,
			expectedNil:   false,
			expectedError: false,
		},
		{
			name:          "finding not found",
			findingID:     "finding-1",
			storeFinding:  nil,
			storeErr:      nil,
			expectedNil:   true,
			expectedError: true,
		},
		{
			name:          "store error",
			findingID:     "finding-1",
			storeFinding:  nil,
			storeErr:      errors.New("store error"),
			expectedNil:   true,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getByFindingIDFunc: func(ctx context.Context, findingID string) (*models.Finding, error) {
					return tc.storeFinding, tc.storeErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.Get(ctx, logger, subject, tc.findingID)

			if tc.expectedError {
				require.Error(t, err)
				if tc.storeErr != nil {
					assert.Contains(t, err.Error(), "failed to get finding from store")
				} else {
					assert.Equal(t, service.ErrFindingNotFound, err)
				}
			} else {
				require.NoError(t, err)
			}

			if tc.expectedNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tc.storeFinding.FindingID, result.FindingID)
			}
		})
	}
}

func TestFindingService_Create(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testFinding := newTestFinding("finding-1")

	testCases := []struct {
		name           string
		finding        *models.Finding
		storeErr       error
		expectedError bool
		errorContains string
	}{
		{
			name:           "successful create",
			finding:        testFinding,
			storeErr:       nil,
			expectedError: false,
		},
		{
			name:           "store error",
			finding:        testFinding,
			storeErr:       errors.New("store error"),
			expectedError: true,
			errorContains: "failed to create finding",
		},
		{
			name:           "empty findingId",
			finding:        &models.Finding{FindingType: models.FindingTypeKnownAttackPatternDetected, Severity: models.FindingSeverityHigh, Title: "test"},
			storeErr:       nil,
			expectedError: true,
			errorContains: "findingId is required",
		},
		{
			name:           "empty findingType",
			finding:        &models.Finding{FindingID: "finding-1", Severity: models.FindingSeverityHigh, Title: "test"},
			storeErr:       nil,
			expectedError: true,
			errorContains: "findingType is required",
		},
		{
			name:           "empty severity",
			finding:        &models.Finding{FindingID: "finding-1", FindingType: models.FindingTypeKnownAttackPatternDetected, Title: "test"},
			storeErr:       nil,
			expectedError: true,
			errorContains: "severity is required",
		},
		{
			name:           "empty title",
			finding:        &models.Finding{FindingID: "finding-1", FindingType: models.FindingTypeKnownAttackPatternDetected, Severity: models.FindingSeverityHigh},
			storeErr:       nil,
			expectedError: true,
			errorContains: "title is required",
		},
		{
			name:           "invalid finding type",
			finding:        &models.Finding{FindingID: "finding-1", FindingType: "invalid", Severity: models.FindingSeverityHigh, Title: "test"},
			storeErr:       nil,
			expectedError: true,
			errorContains: "invalid finding type",
		},
		{
			name:           "invalid severity",
			finding:        &models.Finding{FindingID: "finding-1", FindingType: models.FindingTypeKnownAttackPatternDetected, Severity: "invalid", Title: "test"},
			storeErr:       nil,
			expectedError: true,
			errorContains: "invalid severity",
		},
		{
			name:           "invalid lifecycle status",
			finding:        &models.Finding{FindingID: "finding-1", FindingType: models.FindingTypeKnownAttackPatternDetected, Severity: models.FindingSeverityHigh, Title: "test", Lifecycle: models.FindingLifecycle{Status: "invalid"}},
			storeErr:       nil,
			expectedError: true,
			errorContains: "invalid lifecycle status",
		},
		{
			name:           "invalid verification status",
			finding:        &models.Finding{FindingID: "finding-1", FindingType: models.FindingTypeKnownAttackPatternDetected, Severity: models.FindingSeverityHigh, Title: "test", Verification: models.FindingVerification{Status: "invalid"}},
			storeErr:       nil,
			expectedError: true,
			errorContains: "invalid verification status",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getByFindingIDFunc: func(ctx context.Context, findingID string) (*models.Finding, error) {
					// Return nil to indicate finding doesn't exist
					return nil, nil
				},
				createFunc: func(ctx context.Context, finding *models.Finding) error {
					return tc.storeErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.Create(ctx, logger, subject, tc.finding)

			if tc.expectedError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.finding.FindingID, result.FindingID)
			}
		})
	}
}

func TestFindingService_UpdateLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	newFinding := func() *models.Finding {
		return &models.Finding{
			FindingID:   "finding-1",
			FindingType: models.FindingTypeKnownAttackPatternDetected,
			Severity:    models.FindingSeverityHigh,
			AssetID:     "asset-1",
			DefconID:    "defcon-1",
			Title:       "Test Finding",
			OccurredAt:  time.Now().UTC(),
			Confidence:  0.95,
			Lifecycle:   models.FindingLifecycle{Status: models.FindingLifecycleStatusOpen},
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
	}

	testCases := []struct {
		name          string
		findingID     string
		req           models.UpdateFindingLifecycleRequest
		storeFinding  *models.Finding
		storeErr      error
		updateErr     error
		expectedError bool
		expectStatus  models.FindingLifecycleStatus
	}{
		{
			name:          "successful lifecycle update",
			findingID:     "finding-1",
			req:           models.UpdateFindingLifecycleRequest{Status: models.FindingLifecycleStatusOpen},
			storeFinding:  newFinding(),
			storeErr:      nil,
			updateErr:     nil,
			expectedError: false,
			expectStatus:  models.FindingLifecycleStatusOpen,
		},
		{
			name:          "finding not found",
			findingID:     "finding-1",
			req:           models.UpdateFindingLifecycleRequest{Status: models.FindingLifecycleStatusOpen},
			storeFinding:  nil,
			storeErr:      nil,
			updateErr:     nil,
			expectedError: true,
		},
		{
			name:          "store error on get",
			findingID:     "finding-1",
			req:           models.UpdateFindingLifecycleRequest{Status: models.FindingLifecycleStatusOpen},
			storeFinding:  nil,
			storeErr:      errors.New("get error"),
			updateErr:     nil,
			expectedError: true,
		},
		{
			name:          "store error on update",
			findingID:     "finding-1",
			req:           models.UpdateFindingLifecycleRequest{Status: models.FindingLifecycleStatusOpen},
			storeFinding:  newFinding(),
			storeErr:      nil,
			updateErr:     errors.New("update error"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getByFindingIDFunc: func(ctx context.Context, findingID string) (*models.Finding, error) {
					return tc.storeFinding, tc.storeErr
				},
				updateFunc: func(ctx context.Context, finding *models.Finding) error {
					return tc.updateErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.UpdateLifecycle(ctx, logger, subject, tc.findingID, tc.req)

			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.expectStatus, result.Lifecycle.Status)
			}
		})
	}
}

func TestFindingService_UpdateVerification(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	newFinding := func() *models.Finding {
		return &models.Finding{
			FindingID:    "finding-1",
			FindingType:  models.FindingTypeKnownAttackPatternDetected,
			Severity:     models.FindingSeverityHigh,
			AssetID:      "asset-1",
			DefconID:     "defcon-1",
			Title:        "Test Finding",
			OccurredAt:   time.Now().UTC(),
			Confidence:   0.95,
			Verification: models.FindingVerification{Status: models.FindingVerificationStatusUnverified},
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		}
	}

	testCases := []struct {
		name          string
		findingID     string
		req           models.UpdateFindingVerificationRequest
		storeFinding  *models.Finding
		storeErr      error
		updateErr     error
		expectedError bool
		expectStatus  models.FindingVerificationStatus
	}{
		{
			name:          "successful verification update",
			findingID:     "finding-1",
			req:           models.UpdateFindingVerificationRequest{Status: models.FindingVerificationStatusVerified},
			storeFinding:  newFinding(),
			storeErr:      nil,
			updateErr:     nil,
			expectedError: false,
			expectStatus:  models.FindingVerificationStatusVerified,
		},
		{
			name:          "finding not found",
			findingID:     "finding-1",
			req:           models.UpdateFindingVerificationRequest{Status: models.FindingVerificationStatusVerified},
			storeFinding:  nil,
			storeErr:      nil,
			updateErr:     nil,
			expectedError: true,
		},
		{
			name:          "store error on get",
			findingID:     "finding-1",
			req:           models.UpdateFindingVerificationRequest{Status: models.FindingVerificationStatusVerified},
			storeFinding:  nil,
			storeErr:      errors.New("get error"),
			updateErr:     nil,
			expectedError: true,
		},
		{
			name:          "store error on update",
			findingID:     "finding-1",
			req:           models.UpdateFindingVerificationRequest{Status: models.FindingVerificationStatusVerified},
			storeFinding:  newFinding(),
			storeErr:      nil,
			updateErr:     errors.New("update error"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getByFindingIDFunc: func(ctx context.Context, findingID string) (*models.Finding, error) {
					return tc.storeFinding, tc.storeErr
				},
				updateFunc: func(ctx context.Context, finding *models.Finding) error {
					return tc.updateErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.UpdateVerification(ctx, logger, subject, tc.findingID, tc.req)

			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.expectStatus, result.Verification.Status)
			}
		})
	}
}

func TestFindingService_MarkStale(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	staleDuration := 24 * time.Hour

	newFinding := func(occurredAt time.Duration) *models.Finding {
		occurredAtTime := time.Now().UTC().Add(occurredAt)
		lastCheckedTime := occurredAtTime
		staleAfter := time.Now().UTC().Add(24 * time.Hour)
		return &models.Finding{
			FindingID:   "finding-" + occurredAt.String(),
			FindingType: models.FindingTypeKnownAttackPatternDetected,
			Severity:    models.FindingSeverityHigh,
			AssetID:     "asset-1",
			DefconID:    "defcon-1",
			Title:       "Test Finding",
			OccurredAt:  occurredAtTime,
			Confidence:  0.95,
			Lifecycle:   models.FindingLifecycle{Status: models.FindingLifecycleStatusOpen},
			Freshness: models.FindingFreshness{
				Status:      models.FindingFreshnessStatusFresh,
				StaleAfter:  &staleAfter,
				LastChecked: &lastCheckedTime,
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
	}

	testCases := []struct {
		name          string
		storeList     *models.FindingListResponse
		storeListErr  error
		updateErr     error
		expectedCount int
		expectedError bool
	}{
		{
			name: "successful mark stale",
			storeList: &models.FindingListResponse{
				Items: []*models.Finding{
					newFinding(-1 * time.Hour),  // Fresh
					newFinding(-25 * time.Hour), // Stale
				},
				TotalCount: 2,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			updateErr:     nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "store error on list",
			storeList:     nil,
			storeListErr:  errors.New("list error"),
			updateErr:     nil,
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				listFunc: func(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
				updateFunc: func(ctx context.Context, finding *models.Finding) error {
					return tc.updateErr
				},
			}

			svc := service.NewFindingService(store, logger)

			count, err := svc.MarkStale(ctx, logger, subject, staleDuration)

			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCount, count)
			}
		})
	}
}

func TestFindingService_GetByAsset(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testFindings := []*models.Finding{newTestFinding("finding-1")}

	testCases := []struct {
		name          string
		assetID       string
		opts          models.ListFindingsOptions
		storeList     *models.FindingListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:    "successful get by asset",
			assetID: "asset-1",
			opts:    models.ListFindingsOptions{},
			storeList: &models.FindingListResponse{
				Items:      testFindings,
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "store error",
			assetID:       "asset-1",
			opts:          models.ListFindingsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getByAssetIDFunc: func(ctx context.Context, assetID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.GetByAsset(ctx, logger, subject, tc.assetID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get findings by asset")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestFindingService_GetByDefcon(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testFindings := []*models.Finding{newTestFinding("finding-1")}

	testCases := []struct {
		name          string
		defconID      string
		opts          models.ListFindingsOptions
		storeList     *models.FindingListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:     "successful get by defcon",
			defconID: "defcon-1",
			opts:     models.ListFindingsOptions{},
			storeList: &models.FindingListResponse{
				Items:      testFindings,
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "store error",
			defconID:      "defcon-1",
			opts:          models.ListFindingsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getByDefconIDFunc: func(ctx context.Context, defconID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.GetByDefcon(ctx, logger, subject, tc.defconID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get findings by defcon")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestFindingService_GetByType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testFindings := []*models.Finding{newTestFinding("finding-1")}

	testCases := []struct {
		name          string
		findingType   models.FindingType
		opts          models.ListFindingsOptions
		storeList     *models.FindingListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:        "successful get by type",
			findingType: models.FindingTypeKnownAttackPatternDetected,
			opts:        models.ListFindingsOptions{},
			storeList: &models.FindingListResponse{
				Items:      testFindings,
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "store error",
			findingType:   models.FindingTypeKnownAttackPatternDetected,
			opts:          models.ListFindingsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
		{
			name:          "invalid finding type",
			findingType:   models.FindingType("invalid-type"),
			opts:          models.ListFindingsOptions{},
			storeList:     nil,
			storeListErr:  nil,
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getByFindingTypeFunc: func(ctx context.Context, findingType models.FindingType, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.GetByType(ctx, logger, subject, tc.findingType, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				switch tc.name {
				case "store error":
					assert.Contains(t, err.Error(), "failed to get findings by type")
				case "invalid finding type":
					assert.Contains(t, err.Error(), "invalid finding type")
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestFindingService_GetStale(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testFindings := []*models.Finding{newTestFinding("finding-1")}

	testCases := []struct {
		name          string
		opts          models.ListFindingsOptions
		storeList     *models.FindingListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name: "successful get stale",
			opts: models.ListFindingsOptions{},
			storeList: &models.FindingListResponse{
				Items:      testFindings,
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "store error",
			opts:          models.ListFindingsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockFindingStore{
				getStaleFunc: func(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewFindingService(store, logger)

			result, err := svc.GetStale(ctx, logger, subject, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get stale findings")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestFindingService_isValidLifecycleTransition(t *testing.T) {
	t.Parallel()

	logger := logr.Discard()

	svc := service.NewFindingService(nil, logger)

	// Test valid transitions
	validTransitions := []struct {
		from models.FindingLifecycleStatus
		to   models.FindingLifecycleStatus
	}{
		{models.FindingLifecycleStatusOpen, models.FindingLifecycleStatusResolved},
		{models.FindingLifecycleStatusOpen, models.FindingLifecycleStatusClosed},
		{models.FindingLifecycleStatusResolved, models.FindingLifecycleStatusClosed},
		{models.FindingLifecycleStatusOpen, models.FindingLifecycleStatusOpen},
		{models.FindingLifecycleStatusResolved, models.FindingLifecycleStatusResolved},
		{models.FindingLifecycleStatusClosed, models.FindingLifecycleStatusClosed},
	}

	for _, tc := range validTransitions {
		t.Run(fmt.Sprintf("valid_%s_to_%s", tc.from, tc.to), func(t *testing.T) {
			t.Parallel()
			assert.True(t, svc.IsValidLifecycleTransition(tc.from, tc.to))
		})
	}

	// Test invalid transitions
	invalidTransitions := []struct {
		from models.FindingLifecycleStatus
		to   models.FindingLifecycleStatus
	}{
		{models.FindingLifecycleStatusClosed, models.FindingLifecycleStatusOpen},
		{models.FindingLifecycleStatusClosed, models.FindingLifecycleStatusResolved},
		{models.FindingLifecycleStatusResolved, models.FindingLifecycleStatusOpen},
		{models.FindingLifecycleStatusClosed, models.FindingLifecycleStatusClosed}, // This is valid (same state)
	}

	for _, tc := range invalidTransitions {
		t.Run(fmt.Sprintf("invalid_%s_to_%s", tc.from, tc.to), func(t *testing.T) {
			t.Parallel()
			// Skip the valid same-state transition
			if tc.from == tc.to {
				t.Skip("Same state transition is valid")
			}
			assert.False(t, svc.IsValidLifecycleTransition(tc.from, tc.to))
		})
	}
}

func TestFindingService_ValidationFunctions(t *testing.T) {
	t.Parallel()

	logger := logr.Discard()

	svc := service.NewFindingService(nil, logger)

	// Test isValidFindingType
	t.Run("isValidFindingType", func(t *testing.T) {
		t.Parallel()

		validTypes := []models.FindingType{
			models.FindingTypeKnownAttackPatternDetected,
			models.FindingTypeLateralMovementSuspected,
			models.FindingTypeNetworkPolicyViolationDetected,
			models.FindingTypeConfigDriftUnauthorized,
			models.FindingTypeConfigBaselineMissing,
		}

		for _, ft := range validTypes {
			assert.True(t, svc.IsValidFindingType(ft), "expected %s to be valid", ft)
		}

		// Test invalid type
		assert.False(t, svc.IsValidFindingType("invalid_type"))
	})

	// Test isValidSeverity
	t.Run("isValidSeverity", func(t *testing.T) {
		t.Parallel()

		validSeverities := []models.FindingSeverity{
			models.FindingSeverityCritical,
			models.FindingSeverityHigh,
			models.FindingSeverityMedium,
			models.FindingSeverityLow,
			models.FindingSeverityInfo,
		}

		for _, s := range validSeverities {
			assert.True(t, svc.IsValidSeverity(s), "expected %s to be valid", s)
		}

		// Test invalid severity
		assert.False(t, svc.IsValidSeverity("invalid_severity"))
	})

	// Test isValidLifecycleStatus
	t.Run("isValidLifecycleStatus", func(t *testing.T) {
		t.Parallel()

		validStatuses := []models.FindingLifecycleStatus{
			models.FindingLifecycleStatusOpen,
			models.FindingLifecycleStatusResolved,
			models.FindingLifecycleStatusClosed,
		}

		for _, s := range validStatuses {
			assert.True(t, svc.IsValidLifecycleStatus(s), "expected %s to be valid", s)
		}

		// Test invalid status
		assert.False(t, svc.IsValidLifecycleStatus("invalid_status"))
	})

	// Test isValidVerificationStatus
	t.Run("isValidVerificationStatus", func(t *testing.T) {
		t.Parallel()

		validStatuses := []models.FindingVerificationStatus{
			models.FindingVerificationStatusUnverified,
			models.FindingVerificationStatusVerified,
			models.FindingVerificationStatusFalsePositive,
		}

		for _, s := range validStatuses {
			assert.True(t, svc.IsValidVerificationStatus(s), "expected %s to be valid", s)
		}

		// Test invalid status
		assert.False(t, svc.IsValidVerificationStatus("invalid_status"))
	})

	// Test isValidFreshnessStatus
	t.Run("isValidFreshnessStatus", func(t *testing.T) {
		t.Parallel()

		validStatuses := []models.FindingFreshnessStatus{
			models.FindingFreshnessStatusFresh,
			models.FindingFreshnessStatusStale,
		}

		for _, s := range validStatuses {
			assert.True(t, svc.IsValidFreshnessStatus(s), "expected %s to be valid", s)
		}

		// Test invalid status
		assert.False(t, svc.IsValidFreshnessStatus("invalid_status"))
	})
}
