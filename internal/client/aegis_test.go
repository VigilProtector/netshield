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

// testHTTPClient is a mock HTTPClient for testing.
type testHTTPClient struct {
	getFunc func(ctx context.Context, path string) (*Response, error)
}

func (t *testHTTPClient) Get(ctx context.Context, path string) (*Response, error) {
	if t.getFunc != nil {
		return t.getFunc(ctx, path)
	}
	return nil, nil
}

// =============================================================================
// AegisClient Tests
// =============================================================================

func TestAegisClient_GetAsset_Success(t *testing.T) {
	mockAsset := crossbc.AegisAssetDetail{
		ID:               "mock-asset",
		PrimaryIPAddress:  "192.168.1.1",
		Hostname:         "mock-host",
		Criticality:      "high",
		AssetType:        "server",
		Zone:             "dmz",
		DefconID:         "defcon-1",
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/aegis/v1/assets/mock-asset" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(map[string]interface{}{"data": mockAsset})
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	asset, err := client.GetAsset(ctx, "mock-asset")
	if err != nil {
		t.Fatalf("GetAsset() error = %v", err)
	}
	if asset == nil {
		t.Fatal("GetAsset() returned nil")
	}
	if asset.ID != "mock-asset" {
		t.Errorf("Asset.ID = %v, want %v", asset.ID, "mock-asset")
	}
}

func TestAegisClient_GetAsset_NotFound(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAsset(ctx, "not-found")
	if err == nil {
		t.Fatal("GetAsset() expected error, got nil")
	}
	if !errors.Is(err, ErrAssetNotFound) {
		t.Errorf("Error = %v, want %v", err, ErrAssetNotFound)
	}
}

func TestAegisClient_GetAsset_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAsset(ctx, "test")
	if err == nil {
		t.Fatal("GetAsset() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestAegisClient_GetAsset_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAsset(ctx, "test")
	if err == nil {
		t.Fatal("GetAsset() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}

func TestAegisClient_GetAsset_HTTPError(t *testing.T) {
	expectedErr := errors.New("connection refused")
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return nil, expectedErr
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAsset(ctx, "test")
	if err == nil {
		t.Fatal("GetAsset() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to GET asset") {
		t.Errorf("Error message should contain GET error, got: %v", err)
	}
}

func TestAegisClient_GetAssetByIP_Success(t *testing.T) {
	mockAsset := crossbc.AegisAssetDetail{
		ID:         "mock-asset-ip",
		Hostname:   "mock-host-ip",
		Criticality: "medium",
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/aegis/v1/assets/by-ip/192.168.1.100" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(map[string]interface{}{"data": mockAsset})
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	asset, err := client.GetAssetByIP(ctx, "192.168.1.100")
	if err != nil {
		t.Fatalf("GetAssetByIP() error = %v", err)
	}
	if asset == nil {
		t.Fatal("GetAssetByIP() returned nil")
	}
	if asset.ID != "mock-asset-ip" {
		t.Errorf("Asset.ID = %v, want %v", asset.ID, "mock-asset-ip")
	}
}

func TestAegisClient_GetAssetByIP_NotFound(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAssetByIP(ctx, "192.168.1.999")
	if err == nil {
		t.Fatal("GetAssetByIP() expected error, got nil")
	}
	if !errors.Is(err, ErrAssetNotFound) {
		t.Errorf("Error = %v, want %v", err, ErrAssetNotFound)
	}
}

func TestAegisClient_GetAssetByIP_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAssetByIP(ctx, "192.168.1.100")
	if err == nil {
		t.Fatal("GetAssetByIP() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestAegisClient_GetAssetByIP_HTTPError(t *testing.T) {
	expectedErr := errors.New("connection refused")
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return nil, expectedErr
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAssetByIP(ctx, "192.168.1.100")
	if err == nil {
		t.Fatal("GetAssetByIP() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to GET asset by IP") {
		t.Errorf("Error message should contain GET error, got: %v", err)
	}
}

func TestAegisClient_GetAssetByIP_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewAegisClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetAssetByIP(ctx, "192.168.1.100")
	if err == nil {
		t.Fatal("GetAssetByIP() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}
