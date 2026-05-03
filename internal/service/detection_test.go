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

// mockDetectionStore implements service.DetectionStorer interface for testing.
type mockDetectionStore struct {
	listFunc             func(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	getByIDFunc          func(ctx context.Context, detectionID string) (*models.Detection, error)
	getByDetectionIDFunc func(ctx context.Context, detectionID string) (*models.Detection, error)
	createFunc           func(ctx context.Context, detection *models.Detection) error
	updateFunc           func(ctx context.Context, detection *models.Detection) error
	deleteFunc           func(ctx context.Context, id string) error
	getBySensorIDFunc    func(ctx context.Context, sensorID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	getByPicketIDFunc    func(ctx context.Context, picketID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	getByRuleSetIDFunc   func(ctx context.Context, ruleSetID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	getByRuleIDFunc      func(ctx context.Context, ruleID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
	getUnprocessedFunc   func(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error)
}

func (m *mockDetectionStore) List(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return m.listFunc(ctx, opts)
}

func (m *mockDetectionStore) GetByID(ctx context.Context, detectionID string) (*models.Detection, error) {
	return m.getByIDFunc(ctx, detectionID)
}

func (m *mockDetectionStore) GetByDetectionID(ctx context.Context, detectionID string) (*models.Detection, error) {
	return m.getByDetectionIDFunc(ctx, detectionID)
}

func (m *mockDetectionStore) Create(ctx context.Context, detection *models.Detection) error {
	return m.createFunc(ctx, detection)
}

func (m *mockDetectionStore) Update(ctx context.Context, detection *models.Detection) error {
	return m.updateFunc(ctx, detection)
}

func (m *mockDetectionStore) Delete(ctx context.Context, id string) error {
	return m.deleteFunc(ctx, id)
}

func (m *mockDetectionStore) GetBySensorID(ctx context.Context, sensorID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return m.getBySensorIDFunc(ctx, sensorID, opts)
}

func (m *mockDetectionStore) GetByPicketID(ctx context.Context, picketID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return m.getByPicketIDFunc(ctx, picketID, opts)
}

func (m *mockDetectionStore) GetByRuleSetID(ctx context.Context, ruleSetID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return m.getByRuleSetIDFunc(ctx, ruleSetID, opts)
}

func (m *mockDetectionStore) GetByRuleID(ctx context.Context, ruleID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return m.getByRuleIDFunc(ctx, ruleID, opts)
}

func (m *mockDetectionStore) GetUnprocessed(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return m.getUnprocessedFunc(ctx, opts)
}

// mockFindingStoreForDetection implements service.FindingStorer interface for detection service tests.
type mockFindingStoreForDetection struct {
	createFunc func(ctx context.Context, finding *models.Finding) error
}

func (m *mockFindingStoreForDetection) List(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return nil, nil
}

func (m *mockFindingStoreForDetection) GetByID(ctx context.Context, findingID string) (*models.Finding, error) {
	return nil, nil
}

func (m *mockFindingStoreForDetection) GetByFindingID(ctx context.Context, findingID string) (*models.Finding, error) {
	return nil, nil
}

func (m *mockFindingStoreForDetection) Create(ctx context.Context, finding *models.Finding) error {
	return m.createFunc(ctx, finding)
}

func (m *mockFindingStoreForDetection) Update(ctx context.Context, finding *models.Finding) error {
	return nil
}

func (m *mockFindingStoreForDetection) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockFindingStoreForDetection) GetByAssetID(ctx context.Context, assetID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return nil, nil
}

func (m *mockFindingStoreForDetection) GetByDefconID(ctx context.Context, defconID string, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return nil, nil
}

func (m *mockFindingStoreForDetection) GetByFindingType(ctx context.Context, findingType models.FindingType, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return nil, nil
}

func (m *mockFindingStoreForDetection) GetStale(ctx context.Context, opts models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return nil, nil
}

// mockFlowSeekerClient implements service.FlowSeekerClient interface for testing.
type mockFlowSeekerClient struct {
	getFlowContextFunc func(ctx context.Context, srcIP, dstIP string, startTime, endTime time.Time) (*service.FlowContext, error)
}

func (m *mockFlowSeekerClient) GetFlowContext(ctx context.Context, srcIP, dstIP string, startTime, endTime time.Time) (*service.FlowContext, error) {
	return m.getFlowContextFunc(ctx, srcIP, dstIP, startTime, endTime)
}

// Helper to create a test detection
func newTestDetection(detectionID string) *models.Detection {
	now := time.Now().UTC()
	return &models.Detection{
		DetectionID: detectionID,
		SensorID:    "sensor-1",
		PicketID:    "picket-1",
		RuleSetID:   "ruleset-1",
		RuleID:      "rule-1",
		EventType:   models.DetectionEventTypeAlert,
		Timestamp:   now,
		SourceIP:    "192.168.1.1",
		DestIP:      "10.0.0.1",
		SourcePort:  12345,
		DestPort:    80,
		Proto:       "TCP",
		Action:      "allowed",
		Category:    "malware",
		Severity:    models.RuleSeverityHigh,
		Message:     "Test detection",
		Confidence:  models.ConfidenceHigh,
		AssetID:     "asset-1",
		DefconID:    "defcon-1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func TestDetectionService_List(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{
		newTestDetection("detection-1"),
		newTestDetection("detection-2"),
	}

	testCases := []struct {
		name          string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name: "successful list with no filter",
			opts: models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
				TotalCount: 2,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 2,
			expectedError: false,
		},
		{
			name: "successful list with sensor filter",
			opts: models.ListDetectionsOptions{Filter: models.DetectionFilter{SensorID: "sensor-1"}},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
				TotalCount: 2,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 2,
			expectedError: false,
		},
		{
			name:          "store error",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				listFunc: func(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.List(ctx, logger, subject, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to list detections from store")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_Get(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetection := newTestDetection("detection-1")

	testCases := []struct {
		name           string
		detectionID    string
		storeDetection *models.Detection
		storeErr       error
		expectedNil    bool
		expectedError  bool
	}{
		{
			name:           "successful get",
			detectionID:    "detection-1",
			storeDetection: testDetection,
			storeErr:       nil,
			expectedNil:    false,
			expectedError:  false,
		},
		{
			name:           "detection not found",
			detectionID:    "detection-1",
			storeDetection: nil,
			storeErr:       nil,
			expectedNil:    true,
			expectedError:  true,
		},
		{
			name:           "store error",
			detectionID:    "detection-1",
			storeDetection: nil,
			storeErr:       errors.New("store error"),
			expectedNil:    true,
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByDetectionIDFunc: func(ctx context.Context, detectionID string) (*models.Detection, error) {
					return tc.storeDetection, tc.storeErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.Get(ctx, logger, subject, tc.detectionID)

			if tc.expectedError {
				require.Error(t, err)
				if tc.storeErr != nil {
					assert.Contains(t, err.Error(), "failed to get detection from store")
				} else {
					assert.Equal(t, service.ErrDetectionNotFound, err)
				}
			} else {
				require.NoError(t, err)
			}

			if tc.expectedNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tc.storeDetection.DetectionID, result.DetectionID)
			}
		})
	}
}

func TestDetectionService_Create(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetection := newTestDetection("detection-1")

	testCases := []struct {
		name          string
		detection     *models.Detection
		storeErr      error
		expectedError bool
	}{
		{
			name:          "successful create",
			detection:     testDetection,
			storeErr:      nil,
			expectedError: false,
		},
		{
			name:          "store error",
			detection:     testDetection,
			storeErr:      errors.New("store error"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByDetectionIDFunc: func(ctx context.Context, detectionID string) (*models.Detection, error) {
					// Return nil to indicate detection doesn't exist
					return nil, nil
				},
				createFunc: func(ctx context.Context, detection *models.Detection) error {
					return tc.storeErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.Create(ctx, logger, subject, tc.detection)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create detection")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.detection.DetectionID, result.DetectionID)
			}
		})
	}
}

func TestDetectionService_MarkAsProcessed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetection := newTestDetection("detection-1")

	testCases := []struct {
		name           string
		detectionID    string
		storeDetection *models.Detection
		storeErr       error
		updateErr      error
		expectedError  bool
	}{
		{
			name:           "successful mark as processed",
			detectionID:    "detection-1",
			storeDetection: testDetection,
			storeErr:       nil,
			updateErr:      nil,
			expectedError:  false,
		},
		{
			name:           "detection not found",
			detectionID:    "detection-1",
			storeDetection: nil,
			storeErr:       nil,
			updateErr:      nil,
			expectedError:  true,
		},
		{
			name:           "store error on get",
			detectionID:    "detection-1",
			storeDetection: nil,
			storeErr:       errors.New("get error"),
			updateErr:      nil,
			expectedError:  true,
		},
		{
			name:           "store error on update",
			detectionID:    "detection-1",
			storeDetection: testDetection,
			storeErr:       nil,
			updateErr:      errors.New("update error"),
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByDetectionIDFunc: func(ctx context.Context, detectionID string) (*models.Detection, error) {
					return tc.storeDetection, tc.storeErr
				},
				updateFunc: func(ctx context.Context, detection *models.Detection) error {
					return tc.updateErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			err := svc.MarkAsProcessed(ctx, logger, subject, tc.detectionID)

			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDetectionService_GetBySensorID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		sensorID      string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:     "successful get by sensor",
			sensorID: "sensor-1",
			opts:     models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			sensorID:      "sensor-1",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getBySensorIDFunc: func(ctx context.Context, sensorID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetBySensorID(ctx, logger, subject, tc.sensorID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get detections by sensor")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_GetByPicketID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		picketID      string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:     "successful get by picket",
			picketID: "picket-1",
			opts:     models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			picketID:      "picket-1",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByPicketIDFunc: func(ctx context.Context, picketID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetByPicketID(ctx, logger, subject, tc.picketID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get detections by picket")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_GetByRuleSetID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		ruleSetID     string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:      "successful get by ruleset",
			ruleSetID: "ruleset-1",
			opts:      models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			ruleSetID:     "ruleset-1",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByRuleSetIDFunc: func(ctx context.Context, ruleSetID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetByRuleSetID(ctx, logger, subject, tc.ruleSetID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get detections by ruleSet")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_GetByRuleID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		ruleID        string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:   "successful get by rule",
			ruleID: "rule-1",
			opts:   models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			ruleID:        "rule-1",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByRuleIDFunc: func(ctx context.Context, ruleID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetByRuleID(ctx, logger, subject, tc.ruleID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get detections by rule")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_GetUnprocessed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name: "successful get unprocessed",
			opts: models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getUnprocessedFunc: func(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetUnprocessed(ctx, logger, subject, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get unprocessed detections")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_ProcessDetection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetection := newTestDetection("detection-1")
	// Set CreatedAt == UpdatedAt to simulate unprocessed detection
	now := time.Now().UTC()
	testDetection.CreatedAt = now
	testDetection.UpdatedAt = now

	testCases := []struct {
		name             string
		detectionID      string
		storeDetection   *models.Detection
		storeErr         error
		flowContext      *service.FlowContext
		flowErr          error
		createFindingErr error
		markProcessedErr error
		expectedFinding  bool
		expectedError    bool
		errorContains    string
	}{
		{
			name:        "successful process detection",
			detectionID: "detection-1",
			storeDetection: func() *models.Detection {
				d := newTestDetection("detection-1")
				d.EventType = models.DetectionEventTypeLateralMovement
				return d
			}(),
			storeErr: nil,
			flowContext: &service.FlowContext{
				FlowID:     "flow-1",
				SourceIP:   "192.168.1.1",
				DestIP:     "10.0.0.1",
				Proto:      "TCP",
				SourcePort: 12345,
				DestPort:   80,
				AssetID:    "asset-1",
				DefconID:   "defcon-1",
				StartTime:  now.Add(-5 * time.Minute),
				EndTime:    now.Add(5 * time.Minute),
			},
			flowErr:          nil,
			createFindingErr: nil,
			markProcessedErr: nil,
			expectedFinding:  true,
			expectedError:    false,
		},
		{
			name:            "detection not found",
			detectionID:     "detection-not-found",
			storeDetection:  nil,
			storeErr:        nil,
			flowContext:     nil,
			flowErr:         nil,
			expectedFinding: false,
			expectedError:   true,
			errorContains:   "detection not found",
		},
		{
			name:            "store error on get",
			detectionID:     "detection-1",
			storeDetection:  nil,
			storeErr:        errors.New("store error"),
			flowContext:     nil,
			flowErr:         nil,
			expectedFinding: false,
			expectedError:   true,
			errorContains:   "failed to get detection",
		},
		{
			name:        "detection already processed",
			detectionID: "detection-1",
			storeDetection: func() *models.Detection {
				d := newTestDetection("detection-1")
				// Simulate processed: UpdatedAt > CreatedAt
				d.UpdatedAt = now.Add(time.Minute)
				return d
			}(),
			storeErr:        nil,
			flowContext:     nil,
			flowErr:         nil,
			expectedFinding: false,
			expectedError:   true,
			errorContains:   "already processed",
		},
		{
			name:             "create finding error",
			detectionID:      "detection-1",
			storeDetection:   testDetection,
			storeErr:         nil,
			flowContext:      nil,
			flowErr:          nil,
			createFindingErr: errors.New("create finding error"),
			markProcessedErr: nil,
			expectedFinding:  false,
			expectedError:    true,
			errorContains:    "failed to create finding from detection",
		},
		{
			name:        "flow context enriches detection",
			detectionID: "detection-1",
			storeDetection: func() *models.Detection {
				d := newTestDetection("detection-1")
				d.EventType = models.DetectionEventTypeLateralMovement
				d.AssetID = ""  // No asset ID initially
				d.DefconID = "" // No defcon ID initially
				return d
			}(),
			storeErr: nil,
			flowContext: &service.FlowContext{
				AssetID:  "enriched-asset-1",
				DefconID: "enriched-defcon-1",
			},
			flowErr:          nil,
			createFindingErr: nil,
			markProcessedErr: nil,
			expectedFinding:  true,
			expectedError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByDetectionIDFunc: func(ctx context.Context, detectionID string) (*models.Detection, error) {
					return tc.storeDetection, tc.storeErr
				},
				updateFunc: func(ctx context.Context, detection *models.Detection) error {
					return tc.markProcessedErr
				},
			}

			findingStore := &mockFindingStoreForDetection{
				createFunc: func(ctx context.Context, finding *models.Finding) error {
					return tc.createFindingErr
				},
			}

			flowSeeker := &mockFlowSeekerClient{
				getFlowContextFunc: func(ctx context.Context, srcIP, dstIP string, startTime, endTime time.Time) (*service.FlowContext, error) {
					return tc.flowContext, tc.flowErr
				},
			}

			svc := service.NewDetectionService(store, findingStore, flowSeeker, logger)

			result, err := svc.ProcessDetection(ctx, logger, subject, tc.detectionID)

			if tc.expectedError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				if tc.expectedFinding {
					assert.NotNil(t, result)
					assert.Equal(t, models.FindingTypeLateralMovementSuspected, result.FindingType)
				}
			}
		})
	}
}

func TestDetectionService_GetBySensor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		sensorID      string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:     "successful get by sensor",
			sensorID: "sensor-1",
			opts:     models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			sensorID:      "sensor-1",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getBySensorIDFunc: func(ctx context.Context, sensorID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetBySensor(ctx, logger, subject, tc.sensorID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get detections by sensor")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_GetByPicket(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		picketID      string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:     "successful get by picket",
			picketID: "picket-1",
			opts:     models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			picketID:      "picket-1",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByPicketIDFunc: func(ctx context.Context, picketID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetByPicket(ctx, logger, subject, tc.picketID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get detections by picket")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_GetByRuleSet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetections := []*models.Detection{newTestDetection("detection-1")}

	testCases := []struct {
		name          string
		ruleSetID     string
		opts          models.ListDetectionsOptions
		storeList     *models.DetectionListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name:      "successful get by ruleset",
			ruleSetID: "ruleset-1",
			opts:      models.ListDetectionsOptions{},
			storeList: &models.DetectionListResponse{
				Items:      testDetections,
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
			ruleSetID:     "ruleset-1",
			opts:          models.ListDetectionsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getByRuleSetIDFunc: func(ctx context.Context, ruleSetID string, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			svc := service.NewDetectionService(store, nil, nil, logger)

			result, err := svc.GetByRuleSet(ctx, logger, subject, tc.ruleSetID, tc.opts)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get detections by ruleSet")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestDetectionService_ProcessUnprocessed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testDetection := newTestDetection("detection-1")
	now := time.Now().UTC()
	testDetection.CreatedAt = now
	testDetection.UpdatedAt = now

	testCases := []struct {
		name          string
		batchSize     int
		storeList     *models.DetectionListResponse
		storeListErr  error
		updateErr     error
		createErr     error
		expectedCount int
		expectedError bool
	}{
		{
			name:      "successful process unprocessed - no detections",
			batchSize: 10,
			storeList: &models.DetectionListResponse{
				Items:      []*models.Detection{},
				TotalCount: 0,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			updateErr:     nil,
			createErr:     nil,
			expectedCount: 0,
			expectedError: false,
		},
		{
			name:      "successful process unprocessed - with detections",
			batchSize: 10,
			storeList: &models.DetectionListResponse{
				Items:      []*models.Detection{testDetection},
				TotalCount: 1,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			updateErr:     nil,
			createErr:     nil,
			expectedCount: 1,
			expectedError: false,
		},
		{
			name:          "store error on get unprocessed",
			batchSize:     10,
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			updateErr:     nil,
			createErr:     nil,
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockDetectionStore{
				getUnprocessedFunc: func(ctx context.Context, opts models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
				getByDetectionIDFunc: func(ctx context.Context, detectionID string) (*models.Detection, error) {
					// For ProcessUnprocessed, we need to return detections by ID
					for _, d := range tc.storeList.Items {
						if d.DetectionID == detectionID {
							return d, nil
						}
					}
					return nil, nil
				},
				updateFunc: func(ctx context.Context, detection *models.Detection) error {
					return tc.updateErr
				},
			}

			findingStore := &mockFindingStoreForDetection{
				createFunc: func(ctx context.Context, finding *models.Finding) error {
					return tc.createErr
				},
			}

			flowSeeker := &mockFlowSeekerClient{
				getFlowContextFunc: func(ctx context.Context, srcIP, dstIP string, startTime, endTime time.Time) (*service.FlowContext, error) {
					return nil, nil
				},
			}

			svc := service.NewDetectionService(store, findingStore, flowSeeker, logger)

			count, err := svc.ProcessUnprocessed(ctx, logger, subject, tc.batchSize)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get unprocessed detections")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCount, count)
			}
		})
	}
}
