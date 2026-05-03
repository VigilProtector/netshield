// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"vigilprotector.io/vp-lib/httpclient"
)

func discardLogger() logr.Logger {
	return logr.Discard()
}

// TestNewHTTPClientAdapter tests adapter creation.
func TestNewHTTPClientAdapter(t *testing.T) {
	vpClient := &httpclient.Client{}
	adapter := NewHTTPClientAdapter(vpClient)
	if adapter == nil {
		t.Fatal("NewHTTPClientAdapter() returned nil")
	}
}

// TestNewHTTPClientAdapter_NilClient tests nil client handling.
func TestNewHTTPClientAdapter_NilClient(t *testing.T) {
	adapter := NewHTTPClientAdapter(nil)
	if adapter == nil {
		t.Fatal("NewHTTPClientAdapter() returned nil with nil client")
	}

	ctx := context.Background()
	_, err := adapter.Get(ctx, "/test")
	if err == nil {
		t.Error("Get() expected error for nil client, got nil")
	}
	if !strings.Contains(err.Error(), "nil client") {
		t.Errorf("Error should mention nil client, got: %v", err)
	}
}

// TestNewHTTPClientWithTimeout tests timeout configuration.
func TestNewHTTPClientWithTimeout(t *testing.T) {
	logger := discardLogger()
	adapter := NewHTTPClientWithTimeout(30*time.Second, logger)
	if adapter == nil {
		t.Fatal("NewHTTPClientWithTimeout() returned nil")
	}
}
