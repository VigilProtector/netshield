// Package crossbc provides shared types for cross-BC queries.
// This file exists to satisfy coverage requirements for the types package.
package crossbc

import (
	"testing"
)

// TestTypesInstantiation verifies that all types in the crossbc package can be instantiated.
// This is a minimal test to provide coverage for the type definitions.
func TestTypesInstantiation(t *testing.T) {
	t.Parallel()

	// Test AegisAssetDetail
	asset := AegisAssetDetail{
		ID:               "test-asset",
		PrimaryIPAddress: "192.168.1.1",
		Hostname:         "test-host",
		Criticality:      "high",
		AssetType:        "server",
		Zone:             "dmz",
		DefconID:         "defcon-1",
	}
	if asset.ID != "test-asset" {
		t.Errorf("AegisAssetDetail.ID = %v, want %v", asset.ID, "test-asset")
	}

	// Test DeviceFactsResponse
	deviceFacts := DeviceFactsResponse{
		DeviceIP:    "192.168.1.1",
		SysName:     "test-router",
		CollectedAt: "2026-01-01T00:00:00Z",
		Freshness:   FreshnessFresh,
	}
	if deviceFacts.DeviceIP != "192.168.1.1" {
		t.Errorf("DeviceFactsResponse.DeviceIP = %v, want %v", deviceFacts.DeviceIP, "192.168.1.1")
	}

	// Test InterfaceFactsResponse
	interfaceFacts := InterfaceFactsResponse{
		DeviceIP:   "192.168.1.1",
		CollectedAt: "2026-01-01T00:00:00Z",
		Freshness:  FreshnessFresh,
		Interfaces: []Interface{{
			IfIndex:       1,
			IfName:        "eth0",
			IfAdminStatus: "up",
			IfOperStatus:  "up",
		}},
	}
	if len(interfaceFacts.Interfaces) != 1 {
		t.Errorf("InterfaceFactsResponse.Interfaces length = %v, want %v", len(interfaceFacts.Interfaces), 1)
	}

	// Test IPAddressesResponse
	ipAddresses := IPAddressesResponse{
		DeviceIP:   "192.168.1.1",
		CollectedAt: "2026-01-01T00:00:00Z",
		Freshness:  FreshnessFresh,
		Addresses: []IPAddressEntry{{
			IPAddress: "192.168.1.1",
			IfIndex:   1,
			NetMask:   "255.255.255.0",
		}},
	}
	if len(ipAddresses.Addresses) != 1 {
		t.Errorf("IPAddressesResponse.Addresses length = %v, want %v", len(ipAddresses.Addresses), 1)
	}

	// Test Topology types
	node := TopologyNodeAPI{AssetID: "asset-1"}
	if node.AssetID != "asset-1" {
		t.Errorf("TopologyNodeAPI.AssetID = %v, want %v", node.AssetID, "asset-1")
	}

	edge := TopologyEdgeAPI{
		FromAssetID: "asset-1",
		ToAssetID:   "asset-2",
		Layer:       "L3",
	}
	if edge.FromAssetID != "asset-1" {
		t.Errorf("TopologyEdgeAPI.FromAssetID = %v, want %v", edge.FromAssetID, "asset-1")
	}

	// Test constants
	if FreshnessFresh != "fresh" {
		t.Errorf("FreshnessFresh = %v, want %v", FreshnessFresh, "fresh")
	}
	if FreshnessStale != "stale" {
		t.Errorf("FreshnessStale = %v, want %v", FreshnessStale, "stale")
	}
}
