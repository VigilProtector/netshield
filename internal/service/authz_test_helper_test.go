package service

import (
	"context"

	"vigilprotector.io/vp-lib/authz"
)

// testAllowClient is a mock authz client that allows all requests.
// Used in tests to avoid OPA dependency.
type testAllowClient struct{}

// Evaluate always returns allow=true for test purposes.
func (c *testAllowClient) Evaluate(_ context.Context, _ authz.Input) (*authz.Decision, error) {
	return &authz.Decision{
		Allow:  true,
		Reason: "test-allow-all",
	}, nil
}

// init initializes the authz client for tests.
// This ensures all authorization checks pass during testing.
//
//nolint:gochecknoinits
func init() {
	authz.ResetClient()
	authz.InitClient(&testAllowClient{})
}
