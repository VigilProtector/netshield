// Package service provides the business logic layer for NetShield.
package service

import (
	"vigilprotector.io/netshield/internal/client"
)

// NewAegisClientAdapter creates a new AegisClientAdapter from a client.AegisClient.
// Returns nil if the client is nil.
func NewAegisClientAdapter(aegisClient *client.AegisClient) *AegisClientAdapter {
	if aegisClient == nil {
		return nil
	}

	return &AegisClientAdapter{client: aegisClient}
}

// NewNetSentinelClientAdapter creates a new NetSentinelClientAdapter from a client.NetSentinelClient.
// Returns nil if the client is nil.
func NewNetSentinelClientAdapter(nsClient *client.NetSentinelClient) *NetSentinelClientAdapter {
	if nsClient == nil {
		return nil
	}

	return &NetSentinelClientAdapter{client: nsClient}
}

// NewNetAtlasClientAdapter creates a new NetAtlasClientAdapter from a client.NetAtlasClient.
// Returns nil if the client is nil.
func NewNetAtlasClientAdapter(naClient *client.NetAtlasClient) *NetAtlasClientAdapter {
	if naClient == nil {
		return nil
	}

	return &NetAtlasClientAdapter{client: naClient}
}
