// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"vigilprotector.io/netshield/internal/crossbc"
)

// =============================================================================
// NetAtlasClient Tests
// =============================================================================

func TestNetAtlasClient_GetZoneForAsset_Success(t *testing.T) {
	mockZone := crossbc.TopologyZoneAPI{
		AssetID: "asset-1",
		Members: []string{"asset-2", "asset-3"},
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/netatlas/v1/topology/zones/for-asset/asset-1" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(mockZone)
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	zone, err := client.GetZoneForAsset(ctx, "asset-1")
	if err != nil {
		t.Fatalf("GetZoneForAsset() error = %v", err)
	}
	if zone == nil {
		t.Fatal("GetZoneForAsset() returned nil")
	}
	if zone.AssetID != "asset-1" {
		t.Errorf("AssetID = %v, want %v", zone.AssetID, "asset-1")
	}
}

func TestNetAtlasClient_GetZoneForAsset_NotFound(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	zone, err := client.GetZoneForAsset(ctx, "asset-not-found")
	if err != nil {
		t.Fatalf("GetZoneForAsset() expected no error for not found, got: %v", err)
	}
	if zone != nil {
		t.Errorf("GetZoneForAsset() expected nil for not found, got: %v", zone)
	}
}

func TestNetAtlasClient_GetZoneForAsset_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetZoneForAsset(ctx, "asset-1")
	if err == nil {
		t.Fatal("GetZoneForAsset() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestNetAtlasClient_GetZoneForAsset_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetZoneForAsset(ctx, "asset-1")
	if err == nil {
		t.Fatal("GetZoneForAsset() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}

func TestNetAtlasClient_GetTopologyPath_Success(t *testing.T) {
	mockPath := crossbc.TopologyPathAPI{
		SnapshotVersion: "v1",
		FromAssetID:     "asset-a",
		ToAssetID:       "asset-b",
		Connected:       true,
		HopCount:        2,
		Hops: []crossbc.TopologyPathHopAPI{
			{FromAssetID: "asset-a", ToAssetID: "asset-x", Layer: "L3"},
			{FromAssetID: "asset-x", ToAssetID: "asset-b", Layer: "L3"},
		},
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/netatlas/v1/topology/path/asset-a/asset-b" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(mockPath)
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	path, err := client.GetTopologyPath(ctx, "asset-a", "asset-b")
	if err != nil {
		t.Fatalf("GetTopologyPath() error = %v", err)
	}
	if path == nil {
		t.Fatal("GetTopologyPath() returned nil")
	}
	if path.Connected != true {
		t.Errorf("Connected = %v, want %v", path.Connected, true)
	}
	if path.HopCount != 2 {
		t.Errorf("HopCount = %v, want %v", path.HopCount, 2)
	}
}

func TestNetAtlasClient_GetTopologyPath_NotConnected(t *testing.T) {
	mockPath := crossbc.TopologyPathAPI{
		SnapshotVersion: "v1",
		FromAssetID:     "asset-a",
		ToAssetID:       "asset-b",
		Connected:       false,
		HopCount:        0,
		Hops:            []crossbc.TopologyPathHopAPI{},
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/netatlas/v1/topology/path/asset-a/asset-b" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(mockPath)
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	path, err := client.GetTopologyPath(ctx, "asset-a", "asset-b")
	if err != nil {
		t.Fatalf("GetTopologyPath() error = %v", err)
	}
	if path == nil {
		t.Fatal("GetTopologyPath() returned nil")
	}
	if path.Connected != false {
		t.Errorf("Connected = %v, want %v", path.Connected, false)
	}
}

func TestNetAtlasClient_GetTopologyPath_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetTopologyPath(ctx, "asset-a", "asset-b")
	if err == nil {
		t.Fatal("GetTopologyPath() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestNetAtlasClient_GetTopologyPath_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetTopologyPath(ctx, "asset-a", "asset-b")
	if err == nil {
		t.Fatal("GetTopologyPath() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}

func TestNetAtlasClient_GetLatestSnapshot_Success(t *testing.T) {
	mockSnapshot := crossbc.TopologySnapshotAPI{
		Version:     "v1",
		GeneratedAt: "2024-01-01T00:00:00Z",
		Nodes: []crossbc.TopologyNodeAPI{
			{AssetID: "asset-1"},
			{AssetID: "asset-2"},
		},
		Edges: []crossbc.TopologyEdgeAPI{
			{FromAssetID: "asset-1", ToAssetID: "asset-2", Layer: "L3"},
		},
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/netatlas/v1/topology/snapshot/latest" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(mockSnapshot)
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	snapshot, err := client.GetLatestSnapshot(ctx)
	if err != nil {
		t.Fatalf("GetLatestSnapshot() error = %v", err)
	}
	if snapshot == nil {
		t.Fatal("GetLatestSnapshot() returned nil")
	}
	if snapshot.Version != "v1" {
		t.Errorf("Version = %v, want %v", snapshot.Version, "v1")
	}
	if len(snapshot.Nodes) != 2 {
		t.Errorf("Nodes count = %v, want %v", len(snapshot.Nodes), 2)
	}
}

func TestNetAtlasClient_GetLatestSnapshot_NotFound(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	snapshot, err := client.GetLatestSnapshot(ctx)
	if err != nil {
		t.Fatalf("GetLatestSnapshot() expected no error for not found, got: %v", err)
	}
	if snapshot != nil {
		t.Errorf("GetLatestSnapshot() expected nil for not found, got: %v", snapshot)
	}
}

func TestNetAtlasClient_GetLatestSnapshot_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetLatestSnapshot(ctx)
	if err == nil {
		t.Fatal("GetLatestSnapshot() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestNetAtlasClient_GetLatestSnapshot_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewNetAtlasClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetLatestSnapshot(ctx)
	if err == nil {
		t.Fatal("GetLatestSnapshot() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}
