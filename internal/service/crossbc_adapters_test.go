// Package service provides the business logic layer for NetShield.
package service

import (
	"testing"

	"vigilprotector.io/netshield/internal/client"
)

func TestNewAegisClientAdapter(t *testing.T) {
	t.Parallel()

	t.Run("returns nil for nil client", func(t *testing.T) {
		t.Parallel()

		adapter := NewAegisClientAdapter(nil)
		if adapter != nil {
			t.Errorf("expected nil adapter for nil client, got %+v", adapter)
		}
	})

	t.Run("returns adapter for valid client", func(t *testing.T) {
		t.Parallel()

		mockClient := &client.AegisClient{}
		adapter := NewAegisClientAdapter(mockClient)

		if adapter == nil {
			t.Fatal("expected non-nil adapter for valid client")
		}

		if adapter.client != mockClient {
			t.Errorf("expected adapter.client to be %p, got %p", mockClient, adapter.client)
		}
	})
}

func TestNewNetSentinelClientAdapter(t *testing.T) {
	t.Parallel()

	t.Run("returns nil for nil client", func(t *testing.T) {
		t.Parallel()

		adapter := NewNetSentinelClientAdapter(nil)
		if adapter != nil {
			t.Errorf("expected nil adapter for nil client, got %+v", adapter)
		}
	})

	t.Run("returns adapter for valid client", func(t *testing.T) {
		t.Parallel()

		mockClient := &client.NetSentinelClient{}
		adapter := NewNetSentinelClientAdapter(mockClient)

		if adapter == nil {
			t.Fatal("expected non-nil adapter for valid client")
		}

		if adapter.client != mockClient {
			t.Errorf("expected adapter.client to be %p, got %p", mockClient, adapter.client)
		}
	})
}

func TestNewNetAtlasClientAdapter(t *testing.T) {
	t.Parallel()

	t.Run("returns nil for nil client", func(t *testing.T) {
		t.Parallel()

		adapter := NewNetAtlasClientAdapter(nil)
		if adapter != nil {
			t.Errorf("expected nil adapter for nil client, got %+v", adapter)
		}
	})

	t.Run("returns adapter for valid client", func(t *testing.T) {
		t.Parallel()

		mockClient := &client.NetAtlasClient{}
		adapter := NewNetAtlasClientAdapter(mockClient)

		if adapter == nil {
			t.Fatal("expected non-nil adapter for valid client")
		}

		if adapter.client != mockClient {
			t.Errorf("expected adapter.client to be %p, got %p", mockClient, adapter.client)
		}
	})
}
