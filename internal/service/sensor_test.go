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

// mockSensorStore implements service.SensorStorer interface for testing.
type mockSensorStore struct {
	listFunc          func(ctx context.Context, opts models.ListSensorsOptions) (*models.SensorListResponse, error)
	getByPicketIDFunc func(ctx context.Context, picketID string) (*models.Sensor, error)
	createFunc        func(ctx context.Context, sensor *models.Sensor) error
	updateFunc        func(ctx context.Context, sensor *models.Sensor) error
	getByDefconIDFunc func(ctx context.Context, defconID string) ([]*models.Sensor, error)
}

func (m *mockSensorStore) List(ctx context.Context, opts models.ListSensorsOptions) (*models.SensorListResponse, error) {
	return m.listFunc(ctx, opts)
}

func (m *mockSensorStore) GetByPicketID(ctx context.Context, picketID string) (*models.Sensor, error) {
	return m.getByPicketIDFunc(ctx, picketID)
}

func (m *mockSensorStore) Create(ctx context.Context, sensor *models.Sensor) error {
	return m.createFunc(ctx, sensor)
}

func (m *mockSensorStore) Update(ctx context.Context, sensor *models.Sensor) error {
	return m.updateFunc(ctx, sensor)
}

func (m *mockSensorStore) GetByDefconID(ctx context.Context, defconID string) ([]*models.Sensor, error) {
	return m.getByDefconIDFunc(ctx, defconID)
}

// mockVigilNetClient implements service.VigilNetClient interface for testing.
type mockVigilNetClient struct {
	getDefconNameFunc func(ctx context.Context, defconID string) (string, error)
}

func (m *mockVigilNetClient) GetDefconName(ctx context.Context, defconID string) (string, error) {
	return m.getDefconNameFunc(ctx, defconID)
}

func TestSensorService_List(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testSensors := []*models.Sensor{
		{
			PicketID:  "picket-1",
			DefconID:  "defcon-1",
			Status:    models.SensorStatusActive,
			Health:    models.SensorHealthHealthy,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			PicketID:  "picket-2",
			DefconID:  "defcon-2",
			Status:    models.SensorStatusDegraded,
			Health:    models.SensorHealthUnhealthy,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
	}

	testCases := []struct {
		name          string
		filter        service.ListSensorsOptions
		storeList     *models.SensorListResponse
		storeListErr  error
		expectedCount int
		expectedError bool
	}{
		{
			name: "successful list with no filter",
			filter: service.ListSensorsOptions{
				Filter: models.SensorFilter{},
				Limit:  50,
				Offset: 0,
			},
			storeList: &models.SensorListResponse{
				Items:      testSensors,
				TotalCount: 2,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			expectedCount: 2,
			expectedError: false,
		},
		{
			name: "successful list with defcon filter",
			filter: service.ListSensorsOptions{
				Filter: models.SensorFilter{DefconID: "defcon-1"},
				Limit:  50,
				Offset: 0,
			},
			storeList: &models.SensorListResponse{
				Items:      testSensors[:1],
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
			filter:        service.ListSensorsOptions{},
			storeList:     nil,
			storeListErr:  errors.New("store error"),
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockSensorStore{
				listFunc: func(ctx context.Context, opts models.ListSensorsOptions) (*models.SensorListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
			}

			vigilNet := &mockVigilNetClient{
				getDefconNameFunc: func(ctx context.Context, defconID string) (string, error) {
					return "", nil
				},
			}

			svc := service.NewSensorService(store, vigilNet, logger)

			result, err := svc.List(ctx, logger, subject, tc.filter)

			if tc.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to list sensors from store")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Items, tc.expectedCount)
			}
		})
	}
}

func TestSensorService_Get(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testSensor := &models.Sensor{
		PicketID:  "picket-1",
		DefconID:  "defcon-1",
		Status:    models.SensorStatusActive,
		Health:    models.SensorHealthHealthy,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	testCases := []struct {
		name          string
		picketID      string
		storeSensor   *models.Sensor
		storeErr      error
		expectedNil   bool
		expectedError bool
	}{
		{
			name:          "successful get",
			picketID:      "picket-1",
			storeSensor:   testSensor,
			storeErr:      nil,
			expectedNil:   false,
			expectedError: false,
		},
		{
			name:          "sensor not found",
			picketID:      "picket-1",
			storeSensor:   nil,
			storeErr:      nil,
			expectedNil:   true,
			expectedError: true,
		},
		{
			name:          "store error",
			picketID:      "picket-1",
			storeSensor:   nil,
			storeErr:      errors.New("store error"),
			expectedNil:   true,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockSensorStore{
				getByPicketIDFunc: func(ctx context.Context, picketID string) (*models.Sensor, error) {
					return tc.storeSensor, tc.storeErr
				},
			}

			vigilNet := &mockVigilNetClient{
				getDefconNameFunc: func(ctx context.Context, defconID string) (string, error) {
					return "", nil
				},
			}

			svc := service.NewSensorService(store, vigilNet, logger)

			result, err := svc.Get(ctx, logger, subject, tc.picketID)

			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.expectedNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tc.picketID, result.PicketID)
			}
		})
	}
}

func TestSensorService_Register(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testSensor := &models.Sensor{
		PicketID: "picket-1",
		DefconID: "defcon-1",
		// Status and Health are empty to test default setting in Register
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	testCases := []struct {
		name           string
		sensor         *models.Sensor
		storeErr       error
		vigilNetErr    error
		getDefconName  string
		expectedError  bool
		expectedStatus models.SensorStatus
	}{
		{
			name:           "successful register",
			sensor:         testSensor,
			storeErr:       nil,
			vigilNetErr:    nil,
			getDefconName:  "test-defcon",
			expectedError:  false,
			expectedStatus: models.SensorStatusPending,
		},
		{
			name:           "store error",
			sensor:         testSensor,
			storeErr:       errors.New("store error"),
			vigilNetErr:    nil,
			getDefconName:  "",
			expectedError:  true,
			expectedStatus: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockSensorStore{
				getByPicketIDFunc: func(ctx context.Context, picketID string) (*models.Sensor, error) {
					return nil, nil
				},
				createFunc: func(ctx context.Context, sensor *models.Sensor) error {
					return tc.storeErr
				},
			}

			vigilNet := &mockVigilNetClient{
				getDefconNameFunc: func(ctx context.Context, defconID string) (string, error) {
					return tc.getDefconName, tc.vigilNetErr
				},
			}

			svc := service.NewSensorService(store, vigilNet, logger)

			result, err := svc.Register(ctx, logger, subject, testSensor)

			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.expectedStatus, result.Status)
			}
		})
	}
}

func TestSensorService_UpdateStatus(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	testSensor := &models.Sensor{
		PicketID:  "picket-1",
		DefconID:  "defcon-1",
		Status:    models.SensorStatusActive,
		Health:    models.SensorHealthHealthy,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	testCases := []struct {
		name          string
		picketID      string
		status        models.SensorStatus
		storeSensor   *models.Sensor
		storeErr      error
		updateErr     error
		expectedError bool
	}{
		{
			name:          "successful status update",
			picketID:      "picket-1",
			status:        models.SensorStatusDegraded,
			storeSensor:   testSensor,
			storeErr:      nil,
			updateErr:     nil,
			expectedError: false,
		},
		{
			name:          "sensor not found",
			picketID:      "picket-1",
			status:        models.SensorStatusDegraded,
			storeSensor:   nil,
			storeErr:      nil,
			updateErr:     nil,
			expectedError: true,
		},
		{
			name:          "store error on get",
			picketID:      "picket-1",
			status:        models.SensorStatusDegraded,
			storeSensor:   nil,
			storeErr:      errors.New("store error"),
			updateErr:     nil,
			expectedError: true,
		},
		{
			name:          "store error on update",
			picketID:      "picket-1",
			status:        models.SensorStatusDegraded,
			storeSensor:   testSensor,
			storeErr:      nil,
			updateErr:     errors.New("update error"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &mockSensorStore{
				getByPicketIDFunc: func(ctx context.Context, picketID string) (*models.Sensor, error) {
					return tc.storeSensor, tc.storeErr
				},
				updateFunc: func(ctx context.Context, sensor *models.Sensor) error {
					return tc.updateErr
				},
			}

			svc := service.NewSensorService(store, nil, logger)

			result, err := svc.UpdateStatus(ctx, logger, subject, tc.picketID, tc.status, models.SensorHealthHealthy)

			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestSensorService_MarkStale(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := logr.Discard()
	subject := &types.Subject{Type: "human", ID: "test-user"}

	staleDuration := 24 * time.Hour

	activeSensor := &models.Sensor{
		PicketID:  "picket-1",
		DefconID:  "defcon-1",
		Status:    models.SensorStatusActive,
		Health:    models.SensorHealthHealthy,
		LastSeen:  time.Now().UTC().Add(-25 * time.Hour), // 25 hours ago
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	recentSensor := &models.Sensor{
		PicketID:  "picket-2",
		DefconID:  "defcon-2",
		Status:    models.SensorStatusActive,
		Health:    models.SensorHealthHealthy,
		LastSeen:  time.Now().UTC().Add(-1 * time.Hour), // 1 hour ago
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	testCases := []struct {
		name          string
		storeList     *models.SensorListResponse
		storeListErr  error
		updateErr     error
		expectedCount int
		expectedError bool
	}{
		{
			name: "successful mark stale",
			storeList: &models.SensorListResponse{
				Items:      []*models.Sensor{activeSensor, recentSensor},
				TotalCount: 2,
				Limit:      0,
				Offset:     0,
			},
			storeListErr:  nil,
			updateErr:     nil,
			expectedCount: 1, // Only activeSensor should be marked stale
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

			store := &mockSensorStore{
				listFunc: func(ctx context.Context, opts models.ListSensorsOptions) (*models.SensorListResponse, error) {
					return tc.storeList, tc.storeListErr
				},
				updateFunc: func(ctx context.Context, sensor *models.Sensor) error {
					return tc.updateErr
				},
			}

			svc := service.NewSensorService(store, nil, logger)

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
