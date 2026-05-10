package service

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vigilprotector.io/netshield/internal/models"
	"vigilprotector.io/vp-lib/findings/pullcursor"
)

// getTestLogger returns a no-op logger for testing
func getTestLogger() logr.Logger {
	return logr.Discard()
}

func TestAegisClientAdapter_GetAsset(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test nil client returns nil
	adapter := &AegisClientAdapter{client: nil}
	asset, err := adapter.GetAsset(ctx, "asset-001")

	assert.Nil(t, asset)
	assert.Nil(t, err)
}

func TestNetSentinelClientAdapter_GetDeviceFacts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test nil client returns nil
	adapter := &NetSentinelClientAdapter{client: nil}
	facts, err := adapter.GetDeviceFacts(ctx, "192.168.1.1")

	assert.Nil(t, facts)
	assert.Nil(t, err)
}

func TestNetSentinelClientAdapter_GetInterfaceFacts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test nil client returns nil
	adapter := &NetSentinelClientAdapter{client: nil}
	facts, err := adapter.GetInterfaceFacts(ctx, "192.168.1.1")

	assert.Nil(t, facts)
	assert.Nil(t, err)
}

func TestNetSentinelClientAdapter_GetIPAddresses(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test nil client returns nil
	adapter := &NetSentinelClientAdapter{client: nil}
	addresses, err := adapter.GetIPAddresses(ctx, "192.168.1.1")

	assert.Nil(t, addresses)
	assert.Nil(t, err)
}

func TestNetAtlasClientAdapter_GetTopologyPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test nil client returns nil
	adapter := &NetAtlasClientAdapter{client: nil}
	path, err := adapter.GetTopologyPath(ctx, "asset-001", "asset-002")

	assert.Nil(t, path)
	assert.Nil(t, err)
}

func TestNetAtlasClientAdapter_GetZoneForAsset(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test nil client returns nil
	adapter := &NetAtlasClientAdapter{client: nil}
	zone, err := adapter.GetZoneForAsset(ctx, "asset-001")

	assert.Nil(t, zone)
	assert.Nil(t, err)
}

func TestNetAtlasClientAdapter_GetLatestSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test nil client returns nil
	adapter := &NetAtlasClientAdapter{client: nil}
	snapshot, err := adapter.GetLatestSnapshot(ctx)

	assert.Nil(t, snapshot)
	assert.Nil(t, err)
}

func TestNewFlowSeekerHTTPClient(t *testing.T) {
	t.Parallel()

	logger := getTestLogger()

	t.Run("creates client with valid parameters", func(t *testing.T) {
		t.Parallel()

		client := NewFlowSeekerHTTPClient("http://flowseeker:8080", &http.Client{}, logger)

		assert.NotNil(t, client)
		assert.Equal(t, "http://flowseeker:8080", client.baseURL)
		assert.NotNil(t, client.httpClient)
	})

	t.Run("creates client with empty baseURL", func(t *testing.T) {
		t.Parallel()

		client := NewFlowSeekerHTTPClient("", &http.Client{}, logger)

		assert.NotNil(t, client)
		assert.Equal(t, "", client.baseURL)
	})

	t.Run("creates client with nil http client", func(t *testing.T) {
		t.Parallel()

		client := NewFlowSeekerHTTPClient("http://flowseeker:8080", nil, logger)

		assert.NotNil(t, client)
		assert.Nil(t, client.httpClient)
	})
}

func TestMapFlowSeekerFindingType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		findingType string
		expected    models.DetectionEventType
	}{
		{
			name:        "lateral_movement_suspected type",
			findingType: "network.lateral_movement_suspected",
			expected:    models.DetectionEventTypeLateralMovement,
		},
		{
			name:        "device_reachability_degraded type",
			findingType: "network.device_reachability_degraded",
			expected:    models.DetectionEventTypeAlert,
		},
		{
			name:        "path_inconsistency_detected type",
			findingType: "network.path_inconsistency_detected",
			expected:    models.DetectionEventTypeAnomaly,
		},
		{
			name:        "policy_violation_detected type",
			findingType: "network.policy_violation_detected",
			expected:    models.DetectionEventTypePolicyViolation,
		},
		{
			name:        "known_attack_pattern_detected type",
			findingType: "known_attack_pattern_detected",
			expected:    models.DetectionEventTypeAlert,
		},
		{
			name:        "network anomaly type",
			findingType: "network.anomaly",
			expected:    models.DetectionEventTypeAnomaly,
		},
		{
			name:        "unknown type defaults to flow",
			findingType: "unknown",
			expected:    models.DetectionEventTypeFlow,
		},
		{
			name:        "empty type defaults to flow",
			findingType: "",
			expected:    models.DetectionEventTypeFlow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := mapFlowSeekerFindingType(tc.findingType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNewFlowSeekerConsumer(t *testing.T) {
	t.Parallel()

	logger := getTestLogger()

	t.Run("creates consumer with valid parameters", func(t *testing.T) {
		t.Parallel()

		consumer := NewFlowSeekerConsumer(
			nil, // subscriptionClient
			nil, // detectionService
			nil, // findingService
			nil, // flowSeekerClient
			nil, // lateralMovementDetector
			LateralMovementConfig{}, // lateralMovementConfig
			nil, // aegisClient
			nil, // netSentinelClient
			nil, // netAtlasClient
			logger,
			5*time.Second, // pollInterval
		)

		assert.NotNil(t, consumer)
		assert.Equal(t, 5*time.Second, consumer.pollInterval)
	})

	t.Run("creates consumer with nil parameters", func(t *testing.T) {
		t.Parallel()

		consumer := NewFlowSeekerConsumer(
			nil, nil, nil, nil, nil, LateralMovementConfig{}, nil, nil, nil, logger, 0)

		assert.NotNil(t, consumer)
	})
}

func TestClose(t *testing.T) {
	t.Parallel()

	logger := getTestLogger()

	t.Run("closes without error with nil subscription client", func(t *testing.T) {
		t.Parallel()

		consumer := &FlowSeekerConsumer{
			subscriptionClient: nil,
			logger:              logger,
		}

		err := consumer.Close()
		assert.NoError(t, err, "Close should not return error with nil subscription client")
	})

	t.Run("closes without error with real subscription client", func(t *testing.T) {
		t.Parallel()

		// Build a real (but never started) SubscriptionClient. After the
		// vp-lib v0.31 refactor, the public type wraps an inner generic
		// client; constructing it via NewSubscriptionClient ensures the
		// internal pointer is non-nil so Close is well-defined whether
		// or not Next has ever been called.
		subClient, err := pullcursor.NewSubscriptionClient(pullcursor.SubscriptionClientConfig{
			BaseURL:     "http://test.invalid",
			HTTPClient:  &fakeHTTPDoer{},
			CursorStore: &pullcursor.InMemoryCursorStore{},
		})
		require.NoError(t, err)

		consumer := &FlowSeekerConsumer{
			subscriptionClient: subClient,
			logger:             logger,
		}

		err = consumer.Close()
		assert.NoError(t, err, "Close should not return error")
	})
}

// fakeHTTPDoer is a minimal HTTPDoer used only to construct a
// SubscriptionClient that never actually sends a request.
type fakeHTTPDoer struct{}

func (f *fakeHTTPDoer) Do(_ *http.Request) (*http.Response, error) {
	return nil, errClosedFake
}

var errClosedFake = errors.New("fake doer: not used")
