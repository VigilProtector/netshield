// Package models contains the data models for NetShield service.
package models

import (
	"testing"
	"time"
)

func TestSensorToAPI(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	sensor := &Sensor{
		PicketID:    "picket-001",
		DefconID:    "defcon-001",
		DefconName:  "Defcon 1",
		NodeName:    "node-001",
		Namespace:   "default",
		Status:      SensorStatusActive,
		Health:      SensorHealthHealthy,
		RuleVersion: "v1.0",
		LastSeen:    now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	api := sensor.ToAPI()

	if api.PicketID != sensor.PicketID {
		t.Errorf("ToAPI() PicketID = %v, want %v", api.PicketID, sensor.PicketID)
	}
	if api.DefconID != sensor.DefconID {
		t.Errorf("ToAPI() DefconID = %v, want %v", api.DefconID, sensor.DefconID)
	}
	if api.Status != string(sensor.Status) {
		t.Errorf("ToAPI() Status = %v, want %v", api.Status, string(sensor.Status))
	}
	if api.Health != string(sensor.Health) {
		t.Errorf("ToAPI() Health = %v, want %v", api.Health, string(sensor.Health))
	}
	if api.LastSeen != now.Format(time.RFC3339) {
		t.Errorf("ToAPI() LastSeen = %v, want %v", api.LastSeen, now.Format(time.RFC3339))
	}
}

func TestSensorFromAPI(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		api := &SensorAPI{
			PicketID:    "picket-001",
			DefconID:    "defcon-001",
			DefconName:  "Defcon 1",
			NodeName:    "node-001",
			Namespace:   "default",
			Status:      "active",
			Health:      "healthy",
			RuleVersion: "v1.0",
			LastSeen:    now.Format(time.RFC3339),
			CreatedAt:   now.Format(time.RFC3339),
			UpdatedAt:   now.Format(time.RFC3339),
		}

		sensor, err := api.FromAPI()
		if err != nil {
			t.Fatalf("FromAPI() error = %v", err)
		}

		if sensor.PicketID != api.PicketID {
			t.Errorf("FromAPI() PicketID = %v, want %v", sensor.PicketID, api.PicketID)
		}
		if sensor.DefconID != api.DefconID {
			t.Errorf("FromAPI() DefconID = %v, want %v", sensor.DefconID, api.DefconID)
		}
		if sensor.Status != SensorStatusActive {
			t.Errorf("FromAPI() Status = %v, want %v", sensor.Status, SensorStatusActive)
		}
		if sensor.Health != SensorHealthHealthy {
			t.Errorf("FromAPI() Health = %v, want %v", sensor.Health, SensorHealthHealthy)
		}
	})

	t.Run("invalid lastSeen", func(t *testing.T) {
		t.Parallel()

		api := &SensorAPI{
			LastSeen:  "invalid-time",
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid lastSeen, got nil")
		}
	})

	t.Run("invalid createdAt", func(t *testing.T) {
		t.Parallel()

		api := &SensorAPI{
			LastSeen:  time.Now().Format(time.RFC3339),
			CreatedAt: "invalid-time",
			UpdatedAt: time.Now().Format(time.RFC3339),
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid createdAt, got nil")
		}
	})

	t.Run("invalid updatedAt", func(t *testing.T) {
		t.Parallel()

		api := &SensorAPI{
			LastSeen:  time.Now().Format(time.RFC3339),
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: "invalid-time",
		}

		_, err := api.FromAPI()
		if err == nil {
			t.Error("FromAPI() expected error for invalid updatedAt, got nil")
		}
	})
}
