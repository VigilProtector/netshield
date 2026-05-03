// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
)

// HTTPClient is the subset of vp-lib/httpclient.Client used by all external clients.
// This interface allows for easy mocking in tests.
type HTTPClient interface {
	Get(ctx context.Context, path string) (*Response, error)
}

// Response mirrors the minimal response structure from vp-lib/httpclient.
type Response struct {
	StatusCode int
	Body       []byte
}
