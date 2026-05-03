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
// NetSentinelClient Tests
// =============================================================================

func TestNetSentinelClient_GetDeviceFacts_Success(t *testing.T) {
	mockFacts := crossbc.DeviceFactsResponse{
		DeviceIP:      "192.168.1.1",
		SysName:       "test-router",
		SysDescr:      "Test Router",
		CollectedAt:   "2024-01-01T00:00:00Z",
		Freshness:     crossbc.FreshnessFresh,
		UptimeSeconds: 86400,
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/netsentinel/v1/query/device/192.168.1.1/facts" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(mockFacts)
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	facts, err := client.GetDeviceFacts(ctx, "192.168.1.1")
	if err != nil {
		t.Fatalf("GetDeviceFacts() error = %v", err)
	}
	if facts == nil {
		t.Fatal("GetDeviceFacts() returned nil")
	}
	if facts.DeviceIP != "192.168.1.1" {
		t.Errorf("DeviceIP = %v, want %v", facts.DeviceIP, "192.168.1.1")
	}
}

func TestNetSentinelClient_GetDeviceFacts_NotFound(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	facts, err := client.GetDeviceFacts(ctx, "192.168.1.999")
	if err != nil {
		t.Fatalf("GetDeviceFacts() expected no error for not found, got: %v", err)
	}
	if facts != nil {
		t.Errorf("GetDeviceFacts() expected nil for not found, got: %v", facts)
	}
}

func TestNetSentinelClient_GetDeviceFacts_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetDeviceFacts(ctx, "192.168.1.1")
	if err == nil {
		t.Fatal("GetDeviceFacts() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestNetSentinelClient_GetDeviceFacts_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetDeviceFacts(ctx, "192.168.1.1")
	if err == nil {
		t.Fatal("GetDeviceFacts() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}

func TestNetSentinelClient_GetInterfaceFacts_Success(t *testing.T) {
	mockInterfaces := []crossbc.Interface{
		{IfIndex: 1, IfName: "eth0", IfAlias: "LAN", IfSpeed: 1000000000, IfAdminStatus: "up", IfOperStatus: "up"},
		{IfIndex: 2, IfName: "eth1", IfAlias: "WAN", IfSpeed: 1000000000, IfAdminStatus: "up", IfOperStatus: "up"},
	}

	mockResponse := crossbc.InterfaceFactsResponse{
		DeviceIP:    "192.168.1.1",
		CollectedAt: "2024-01-01T00:00:00Z",
		Freshness:   crossbc.FreshnessFresh,
		Interfaces:  mockInterfaces,
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/netsentinel/v1/query/device/192.168.1.1/interfaces" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(mockResponse)
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	facts, err := client.GetInterfaceFacts(ctx, "192.168.1.1")
	if err != nil {
		t.Fatalf("GetInterfaceFacts() error = %v", err)
	}
	if facts == nil {
		t.Fatal("GetInterfaceFacts() returned nil")
	}
	if len(facts.Interfaces) != 2 {
		t.Errorf("Interfaces count = %v, want %v", len(facts.Interfaces), 2)
	}
}

func TestNetSentinelClient_GetInterfaceFacts_NotFound(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	facts, err := client.GetInterfaceFacts(ctx, "192.168.1.999")
	if err != nil {
		t.Fatalf("GetInterfaceFacts() expected no error for not found, got: %v", err)
	}
	if facts != nil {
		t.Errorf("GetInterfaceFacts() expected nil for not found, got: %v", facts)
	}
}

func TestNetSentinelClient_GetInterfaceFacts_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetInterfaceFacts(ctx, "192.168.1.1")
	if err == nil {
		t.Fatal("GetInterfaceFacts() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestNetSentinelClient_GetInterfaceFacts_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetInterfaceFacts(ctx, "192.168.1.1")
	if err == nil {
		t.Fatal("GetInterfaceFacts() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}

func TestNetSentinelClient_GetIPAddresses_Success(t *testing.T) {
	mockAddresses := []crossbc.IPAddressEntry{
		{IPAddress: "192.168.1.1", IfIndex: 1, NetMask: "255.255.255.0"},
		{IPAddress: "10.0.0.1", IfIndex: 2, NetMask: "255.255.255.0"},
	}

	mockResponse := crossbc.IPAddressesResponse{
		DeviceIP:    "192.168.1.1",
		CollectedAt: "2024-01-01T00:00:00Z",
		Freshness:   crossbc.FreshnessFresh,
		Addresses:   mockAddresses,
	}

	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			if path != "/api/netsentinel/v1/query/device/192.168.1.1/ipaddresses" {
				return nil, errors.New("unexpected path: " + path)
			}
			data, _ := json.Marshal(mockResponse)
			return &Response{StatusCode: 200, Body: data}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	addresses, err := client.GetIPAddresses(ctx, "192.168.1.1")
	if err != nil {
		t.Fatalf("GetIPAddresses() error = %v", err)
	}
	if addresses == nil {
		t.Fatal("GetIPAddresses() returned nil")
	}
	if len(addresses.Addresses) != 2 {
		t.Errorf("Addresses count = %v, want %v", len(addresses.Addresses), 2)
	}
}

func TestNetSentinelClient_GetIPAddresses_NotFound(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	addresses, err := client.GetIPAddresses(ctx, "192.168.1.999")
	if err != nil {
		t.Fatalf("GetIPAddresses() expected no error for not found, got: %v", err)
	}
	if addresses != nil {
		t.Errorf("GetIPAddresses() expected nil for not found, got: %v", addresses)
	}
}

func TestNetSentinelClient_GetIPAddresses_ServerError(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetIPAddresses(ctx, "192.168.1.1")
	if err == nil {
		t.Fatal("GetIPAddresses() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Error message should contain status code, got: %v", err)
	}
}

func TestNetSentinelClient_GetIPAddresses_InvalidJSON(t *testing.T) {
	mockClient := &testHTTPClient{
		getFunc: func(ctx context.Context, path string) (*Response, error) {
			return &Response{StatusCode: 200, Body: []byte("{invalid")}, nil
		},
	}

	client := NewNetSentinelClient("http://mock", mockClient, discardLogger())
	ctx := context.Background()

	_, err := client.GetIPAddresses(ctx, "192.168.1.1")
	if err == nil {
		t.Fatal("GetIPAddresses() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Error message should contain decode error, got: %v", err)
	}
}
