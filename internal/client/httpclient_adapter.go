// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/vp-lib/httpclient"
)

// HTTPClientAdapter wraps vp-lib's httpclient.Client to implement our HTTPClient interface.
type HTTPClientAdapter struct {
	client *httpclient.Client
}

// NewHTTPClientAdapter creates a new HTTPClientAdapter from a vp-lib httpclient.Client.
func NewHTTPClientAdapter(client *httpclient.Client) *HTTPClientAdapter {
	return &HTTPClientAdapter{client: client}
}

// Get implements the HTTPClient interface using the underlying vp-lib client.
func (a *HTTPClientAdapter) Get(ctx context.Context, path string) (*Response, error) {
	if a.client == nil {
		return nil, &nilClientError{path: path}
	}

	resp, err := a.client.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       resp.Body,
	}, nil
}

// nilClientError is returned when the adapter has a nil client.
type nilClientError struct {
	path string
}

func (e *nilClientError) Error() string {
	return "httpclient adapter: nil client cannot make request to " + e.path
}

// NewHTTPClientWithTimeout creates a new vp-lib httpclient.Client with the given timeout
// and wraps it in an HTTPClientAdapter.
func NewHTTPClientWithTimeout(timeout time.Duration, logger logr.Logger) *HTTPClientAdapter {
	cfg := httpclient.Config{
		Timeout:        timeout,
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
	}
	client := httpclient.New(cfg, logger)

	return NewHTTPClientAdapter(client)
}
