// Package crossbc provides shared types for cross-BC queries.
// This package is imported by both client and service packages to avoid circular dependencies.
package crossbc

// AegisAssetDetail holds the asset information needed for context correlation.
// Contains Identity and Criticality information from Aegis.
type AegisAssetDetail struct {
	// ID is the Aegis asset identifier.
	ID string `json:"id"`
	// PrimaryIPAddress is the primary IP address of the asset.
	PrimaryIPAddress string `json:"primaryIpAddress,omitempty"`
	// Hostname is the hostname of the asset.
	Hostname string `json:"hostname,omitempty"`
	// Criticality is the business criticality level of the asset.
	Criticality string `json:"criticality,omitempty"`
	// AssetType is the type/classification of the asset.
	AssetType string `json:"assetType,omitempty"`
	// Zone is the network zone the asset belongs to.
	Zone string `json:"zone,omitempty"`
	// DefconID is the Defcon ID the asset belongs to.
	DefconID string `json:"defconId,omitempty"`
}

// Freshness constants for device/interface facts responses.
const (
	FreshnessFresh = "fresh"
	FreshnessStale = "stale"
)

// DeviceFactsResponse is the live sys* snapshot for one device.
type DeviceFactsResponse struct {
	DeviceIP      string `json:"deviceIp"`
	SysName       string `json:"sysName,omitempty"`
	SysDescr      string `json:"sysDescr,omitempty"`
	SysContact    string `json:"sysContact,omitempty"`
	SysLocation   string `json:"sysLocation,omitempty"`
	UptimeSeconds int    `json:"uptimeSeconds,omitempty"`
	CollectedAt   string `json:"collectedAt"`
	Freshness     string `json:"freshness"`
}

// InterfaceFactsResponse is the live ifTable snapshot for one device.
type InterfaceFactsResponse struct {
	DeviceIP    string      `json:"deviceIp"`
	CollectedAt string      `json:"collectedAt"`
	Freshness   string      `json:"freshness"`
	Interfaces  []Interface `json:"interfaces"`
}

// Interface mirrors the v2 network_device profile per-interface shape.
type Interface struct {
	IfIndex       int    `json:"ifIndex"`
	IfName        string `json:"ifName,omitempty"`
	IfAlias       string `json:"ifAlias,omitempty"`
	IfSpeed       uint64 `json:"ifSpeed,omitempty"`
	IfAdminStatus string `json:"ifAdminStatus,omitempty"`
	IfOperStatus  string `json:"ifOperStatus,omitempty"`
}

// IPAddressesResponse is the live snapshot of the RFC1213 ipAdEntTable.
type IPAddressesResponse struct {
	DeviceIP    string           `json:"deviceIp"`
	CollectedAt string           `json:"collectedAt"`
	Freshness   string           `json:"freshness"`
	Addresses   []IPAddressEntry `json:"addresses"`
}

// IPAddressEntry mirrors one row of ipAdEntTable.
type IPAddressEntry struct {
	IPAddress string `json:"ipAddress"`
	IfIndex   int    `json:"ifIndex"`
	NetMask   string `json:"netMask,omitempty"`
}

// TopologyNodeAPI is the response shape of one node in a topology snapshot.
type TopologyNodeAPI struct {
	AssetID string `json:"assetId"`
}

// TopologyEdgeAPI is the response shape of one edge.
type TopologyEdgeAPI struct {
	FromAssetID string `json:"fromAssetId"`
	ToAssetID   string `json:"toAssetId"`
	Layer       string `json:"layer"`
	ObservedAt  string `json:"observedAt"`
	EvidenceRef string `json:"evidenceRef"`
}

// TopologySegmentAPI groups a set of node asset IDs that share a segment.
type TopologySegmentAPI struct {
	AssetID string   `json:"assetId"`
	Members []string `json:"members,omitempty"`
}

// TopologyZoneAPI groups a set of node asset IDs that share a zone.
type TopologyZoneAPI struct {
	AssetID string   `json:"assetId"`
	Members []string `json:"members,omitempty"`
}

// TopologySnapshotAPI is the response representation of a persisted topology snapshot.
type TopologySnapshotAPI struct {
	Version     string               `json:"version"`
	GeneratedAt string               `json:"generatedAt"`
	Nodes       []TopologyNodeAPI    `json:"nodes"`
	Edges       []TopologyEdgeAPI    `json:"edges"`
	Segments    []TopologySegmentAPI `json:"segments,omitempty"`
	Zones       []TopologyZoneAPI    `json:"zones,omitempty"`
}

// TopologyPathHopAPI is one hop in a computed topology path.
type TopologyPathHopAPI struct {
	FromAssetID string `json:"fromAssetId"`
	ToAssetID   string `json:"toAssetId"`
	Layer       string `json:"layer"`
}

// TopologyPathAPI is the response shape for the path endpoint.
type TopologyPathAPI struct {
	SnapshotVersion string               `json:"snapshotVersion"`
	FromAssetID     string               `json:"fromAssetId"`
	ToAssetID       string               `json:"toAssetId"`
	Connected       bool                 `json:"connected"`
	HopCount        int                  `json:"hopCount"`
	Hops            []TopologyPathHopAPI `json:"hops"`
}
