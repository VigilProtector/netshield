// Package models contains the data models for NetShield service.
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Sensor represents a Picket sensor on a Defcon.
// Implements NH-SM-001: Sensor-Datenmodell (nur fuer plattform-managed Pickets).
type Sensor struct {
	ID          bson.ObjectID `bson:"_id,omitempty" json:"-"`
	PicketID    string        `bson:"picketId" json:"picketId"`
	DefconID    string        `bson:"defconId" json:"defconId"`
	DefconName  string        `bson:"defconName" json:"defconName"`
	NodeName    string        `bson:"nodeName" json:"nodeName"`
	Namespace   string        `bson:"namespace" json:"namespace"`
	Status      SensorStatus  `bson:"status" json:"status"`
	Health      SensorHealth  `bson:"health" json:"health"`
	RuleVersion string        `bson:"ruleVersion" json:"ruleVersion"`
	LastSeen    time.Time     `bson:"lastSeen" json:"lastSeen"`
	CreatedAt   time.Time     `bson:"createdAt" json:"createdAt"`
	UpdatedAt   time.Time     `bson:"updatedAt" json:"updatedAt"`
	CreatedBy   string        `bson:"createdBy" json:"createdBy"`
	UpdatedBy   string        `bson:"updatedBy" json:"updatedBy"`
}

// SensorAPI represents a sensor for API responses (camelCase JSON).
type SensorAPI struct {
	PicketID    string    `json:"picketId"`
	DefconID    string    `json:"defconId"`
	DefconName  string    `json:"defconName"`
	NodeName    string    `json:"nodeName"`
	Namespace   string    `json:"namespace"`
	Status      string    `json:"status"`
	Health      string    `json:"health"`
	RuleVersion string    `json:"ruleVersion"`
	LastSeen    string    `json:"lastSeen"`
	CreatedAt   string    `json:"createdAt"`
	UpdatedAt   string    `json:"updatedAt"`
}

// SensorListResponse wraps a list of sensors for API responses.
type SensorListResponse struct {
	Items      []*Sensor `json:"items"`
	TotalCount int       `json:"totalCount"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset"`
}

// SensorStatus represents the operational status of a sensor.
type SensorStatus string

const (
	// SensorStatusPending indicates the sensor is being provisioned.
	SensorStatusPending SensorStatus = "pending"
	// SensorStatusActive indicates the sensor is operational.
	SensorStatusActive SensorStatus = "active"
	// SensorStatusDegraded indicates the sensor has issues but is partially functional.
	SensorStatusDegraded SensorStatus = "degraded"
	// SensorStatusStale indicates the sensor has not sent events for a while.
	SensorStatusStale SensorStatus = "stale"
	// SensorStatusError indicates the sensor is not functional.
	SensorStatusError SensorStatus = "error"
	// SensorStatusDeleting indicates the sensor is being removed.
	SensorStatusDeleting SensorStatus = "deleting"
)

// SensorHealth represents the health status of a sensor.
type SensorHealth string

const (
	// SensorHealthHealthy indicates the sensor is healthy.
	SensorHealthHealthy SensorHealth = "healthy"
	// SensorHealthUnhealthy indicates the sensor has health issues.
	SensorHealthUnhealthy SensorHealth = "unhealthy"
	// SensorHealthUnknown indicates the health status is unknown.
	SensorHealthUnknown SensorHealth = "unknown"
)

// SensorFilter defines filter options for listing sensors.
type SensorFilter struct {
	DefconID string `json:"defconId,omitempty"`
	Status   string `json:"status,omitempty"`
	Health   string `json:"health,omitempty"`
}

// ListSensorsOptions defines options for listing sensors.
type ListSensorsOptions struct {
	Filter  SensorFilter `json:"filter,omitempty"`
	Limit   int          `json:"limit,omitempty"`
	Offset  int          `json:"offset,omitempty"`
	SortBy  string       `json:"sortBy,omitempty"`
	SortAsc bool         `json:"sortAsc,omitempty"`
}

// ToAPI converts a Sensor to a SensorAPI.
func (s *Sensor) ToAPI() *SensorAPI {
	return &SensorAPI{
		PicketID:    s.PicketID,
		DefconID:    s.DefconID,
		DefconName:  s.DefconName,
		NodeName:    s.NodeName,
		Namespace:   s.Namespace,
		Status:      string(s.Status),
		Health:      string(s.Health),
		RuleVersion: s.RuleVersion,
		LastSeen:    s.LastSeen.Format(time.RFC3339),
		CreatedAt:   s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   s.UpdatedAt.Format(time.RFC3339),
	}
}

// FromAPI converts a SensorAPI to a Sensor.
func (s *SensorAPI) FromAPI() (*Sensor, error) {
	lastSeen, err := time.Parse(time.RFC3339, s.LastSeen)
	if err != nil {
		return nil, err
	}
	createdAt, err := time.Parse(time.RFC3339, s.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := time.Parse(time.RFC3339, s.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &Sensor{
		PicketID:    s.PicketID,
		DefconID:    s.DefconID,
		DefconName:  s.DefconName,
		NodeName:    s.NodeName,
		Namespace:   s.Namespace,
		Status:      SensorStatus(s.Status),
		Health:      SensorHealth(s.Health),
		RuleVersion: s.RuleVersion,
		LastSeen:    lastSeen,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}, nil
}
