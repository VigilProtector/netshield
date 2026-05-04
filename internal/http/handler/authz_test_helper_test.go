// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/netshield/internal/service"
	"vigilprotector.io/vp-lib/authn"
	"vigilprotector.io/vp-lib/authz"
	"vigilprotector.io/vp-lib/correlation"
	vplogging "vigilprotector.io/vp-lib/logging"
	"vigilprotector.io/vp-lib/types"
)

// testAuthzClient is a mock authz client for handler tests.
type testAuthzClient struct {
	allow  bool
	reason string
	err    error
}

// Evaluate implements authz.Client.
func (c *testAuthzClient) Evaluate(_ context.Context, _ authz.Input) (*authz.Decision, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &authz.Decision{
		Allow:  c.allow,
		Reason: c.reason,
	}, nil
}

// setupTestRouter creates a test Gin router with logger middleware.
func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add logger and correlation ID to context via middleware
	logger := vplogging.NewLogger("development", "console", "netshield-test", vplogging.LogLevelDebug)
	router.Use(func(c *gin.Context) {
		// Ensure correlation ID exists in request context
		ctx := c.Request.Context()
		if _, ok := correlation.FromContext(ctx); !ok {
			ctx = correlation.WithID(ctx, "test-correlation-123")
			c.Request = c.Request.WithContext(ctx)
		}

		// Set logger in Gin context
		c.Set("Logger", logger)
	})

	return router
}

// initTestAuthz initializes authz with a mock client.
// Returns a cleanup function to restore the original client.
func initTestAuthz(allow bool, reason string, err error) func() {
	// Reset to ensure clean state before setting test client
	authz.ResetClient()
	authz.InitClient(&testAuthzClient{
		allow:  allow,
		reason: reason,
		err:    err,
	})
	return func() {
		// Reset to nil to clean up - tests should set their own state
		authz.ResetClient()
	}
}

// createAuthRequest creates an HTTP request with authentication context and correlation ID.
func createAuthRequest(method, path string) *http.Request {
	ctx := context.Background()
	ctx = correlation.WithID(ctx, "test-correlation-123")

	// Set authentication subject
	testSubject := &types.Subject{
		Type: types.SubjectTypeHuman,
		ID:   "test-user@test.com",
	}
	ctx = authn.WithSubject(ctx, testSubject)

	req := httptest.NewRequest(method, path, nil)
	return req.WithContext(ctx)
}

// mockDetectionService is a mock implementation for testing.
type mockDetectionService struct{}

// List implements service.DetectionServiceInterface.
func (m *mockDetectionService) List(_ context.Context, _ logr.Logger, _ *types.Subject, _ models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return &models.DetectionListResponse{
		Items:      []*models.Detection{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// Get implements service.DetectionServiceInterface.
func (m *mockDetectionService) Get(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.Detection, error) {
	return &models.Detection{
		DetectionID: "det-123",
	}, nil
}

// Create implements service.DetectionServiceInterface.
func (m *mockDetectionService) Create(_ context.Context, _ logr.Logger, _ *types.Subject, _ *models.Detection) (*models.Detection, error) {
	return nil, nil
}

// ProcessDetection implements service.DetectionServiceInterface.
func (m *mockDetectionService) ProcessDetection(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.Finding, error) {
	return &models.Finding{}, nil
}

// MarkAsProcessed implements service.DetectionServiceInterface.
func (m *mockDetectionService) MarkAsProcessed(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) error {
	return nil
}

// GetBySensorID implements service.DetectionServiceInterface.
func (m *mockDetectionService) GetBySensorID(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return &models.DetectionListResponse{
		Items:      []*models.Detection{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// GetByPicketID implements service.DetectionServiceInterface.
func (m *mockDetectionService) GetByPicketID(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return &models.DetectionListResponse{
		Items:      []*models.Detection{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// GetByRuleSetID implements service.DetectionServiceInterface.
func (m *mockDetectionService) GetByRuleSetID(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return &models.DetectionListResponse{
		Items:      []*models.Detection{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// GetByRuleID implements service.DetectionServiceInterface.
func (m *mockDetectionService) GetByRuleID(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return &models.DetectionListResponse{
		Items:      []*models.Detection{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// GetUnprocessed implements service.DetectionServiceInterface.
func (m *mockDetectionService) GetUnprocessed(_ context.Context, _ logr.Logger, _ *types.Subject, _ models.ListDetectionsOptions) (*models.DetectionListResponse, error) {
	return &models.DetectionListResponse{
		Items:      []*models.Detection{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// getMockDetectionService returns a mock detection service for testing.
func getMockDetectionService() service.DetectionServiceInterface {
	return &mockDetectionService{}
}

// mockSensorService is a mock implementation for testing.
type mockSensorService struct{}

// List implements service.SensorServiceInterface.
func (m *mockSensorService) List(_ context.Context, _ logr.Logger, _ *types.Subject, _ service.ListSensorsOptions) (*service.ListSensorsResult, error) {
	return &service.ListSensorsResult{
		Items:      []*models.Sensor{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// Get implements service.SensorServiceInterface.
func (m *mockSensorService) Get(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.Sensor, error) {
	return &models.Sensor{
		PicketID: "picket-1",
	}, nil
}

// Register implements service.SensorServiceInterface.
func (m *mockSensorService) Register(_ context.Context, _ logr.Logger, _ *types.Subject, _ *models.Sensor) (*models.Sensor, error) {
	return &models.Sensor{
		PicketID: "picket-1",
	}, nil
}

// UpdateStatus implements service.SensorServiceInterface.
func (m *mockSensorService) UpdateStatus(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.SensorStatus, _ models.SensorHealth) (*models.Sensor, error) {
	return &models.Sensor{
		PicketID: "picket-1",
	}, nil
}

// UpdateLastSeen implements service.SensorServiceInterface.
func (m *mockSensorService) UpdateLastSeen(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.Sensor, error) {
	return &models.Sensor{
		PicketID: "picket-1",
	}, nil
}

// UpdateRuleVersion implements service.SensorServiceInterface.
func (m *mockSensorService) UpdateRuleVersion(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ string) (*models.Sensor, error) {
	return &models.Sensor{
		PicketID: "picket-1",
	}, nil
}

// getMockSensorService returns a mock sensor service for testing.
func getMockSensorService() service.SensorServiceInterface {
	return &mockSensorService{}
}

// mockRuleSetService is a mock implementation for testing.
type mockRuleSetService struct{}

// List implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) List(_ context.Context, _ logr.Logger, _ *types.Subject, _ models.RuleSetFilter) (*models.RuleSetListResponse, error) {
	return &models.RuleSetListResponse{
		Items:      []*models.RuleSet{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// Get implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) Get(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.RuleSet, error) {
	return &models.RuleSet{}, nil
}

// Create implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) Create(_ context.Context, _ logr.Logger, _ *types.Subject, _ models.CreateRuleSetRequest) (*models.RuleSet, error) {
	return &models.RuleSet{}, nil
}

// Update implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) Update(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.UpdateRuleSetRequest) (*models.RuleSet, error) {
	return &models.RuleSet{}, nil
}

// Delete implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) Delete(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) error {
	return nil
}

// Enable implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) Enable(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.RuleSet, error) {
	return &models.RuleSet{}, nil
}

// Disable implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) Disable(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.RuleSet, error) {
	return &models.RuleSet{}, nil
}

// GetDefault implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) GetDefault(_ context.Context, _ logr.Logger, _ *types.Subject) (*models.RuleSet, error) {
	return &models.RuleSet{}, nil
}

// Render implements service.RuleSetServiceInterface.
func (m *mockRuleSetService) Render(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (string, error) {
	return "rendered-rules", nil
}

// getMockRuleSetService returns a mock ruleSet service for testing.
func getMockRuleSetService() service.RuleSetServiceInterface {
	return &mockRuleSetService{}
}

// mockFindingService is a mock implementation for testing.
type mockFindingService struct{}

// List implements service.FindingServiceInterface.
func (m *mockFindingService) List(_ context.Context, _ logr.Logger, _ *types.Subject, _ models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return &models.FindingListResponse{
		Items:      []*models.Finding{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// Get implements service.FindingServiceInterface.
func (m *mockFindingService) Get(_ context.Context, _ logr.Logger, _ *types.Subject, _ string) (*models.Finding, error) {
	return &models.Finding{}, nil
}

// GetByAsset implements service.FindingServiceInterface.
func (m *mockFindingService) GetByAsset(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return &models.FindingListResponse{
		Items:      []*models.Finding{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// Create implements service.FindingServiceInterface.
func (m *mockFindingService) Create(_ context.Context, _ logr.Logger, _ *types.Subject, _ *models.Finding) (*models.Finding, error) {
	return &models.Finding{}, nil
}

// UpdateLifecycle implements service.FindingServiceInterface.
func (m *mockFindingService) UpdateLifecycle(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.UpdateFindingLifecycleRequest) (*models.Finding, error) {
	return &models.Finding{}, nil
}

// UpdateVerification implements service.FindingServiceInterface.
func (m *mockFindingService) UpdateVerification(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.UpdateFindingVerificationRequest) (*models.Finding, error) {
	return &models.Finding{}, nil
}

// MarkStale implements service.FindingServiceInterface.
func (m *mockFindingService) MarkStale(_ context.Context, _ logr.Logger, _ *types.Subject, _ time.Duration) (int, error) {
	return 0, nil
}

// GetByDefcon implements service.FindingServiceInterface.
func (m *mockFindingService) GetByDefcon(_ context.Context, _ logr.Logger, _ *types.Subject, _ string, _ models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return &models.FindingListResponse{
		Items:      []*models.Finding{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// GetByType implements service.FindingServiceInterface.
func (m *mockFindingService) GetByType(_ context.Context, _ logr.Logger, _ *types.Subject, _ models.FindingType, _ models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return &models.FindingListResponse{
		Items:      []*models.Finding{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// GetStale implements service.FindingServiceInterface.
func (m *mockFindingService) GetStale(_ context.Context, _ logr.Logger, _ *types.Subject, _ models.ListFindingsOptions) (*models.FindingListResponse, error) {
	return &models.FindingListResponse{
		Items:      []*models.Finding{},
		TotalCount: 0,
		Limit:      0,
		Offset:     0,
	}, nil
}

// getMockFindingService returns a mock finding service for testing.
func getMockFindingService() service.FindingServiceInterface {
	return &mockFindingService{}
}
