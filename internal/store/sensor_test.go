// Package store provides the data access layer for NetShield.
package store

import (
	"testing"
)

// TestNewSensorStore verifies that NewSensorStore creates a properly initialized store.
func TestNewSensorStore(t *testing.T) {
	t.Parallel()

	// Note: This test is limited because we're directly using *mongo.Collection
	// In a proper architecture, we would use dependency injection with an interface.
	// For now, we just verify the error constants are properly defined.

	// Test error constants
	if ErrSensorNotFound == nil {
		t.Error("ErrSensorNotFound should not be nil")
	}

	if ErrSensorAlreadyExists == nil {
		t.Error("ErrSensorAlreadyExists should not be nil")
	}

	if ErrInvalidID == nil {
		t.Error("ErrInvalidID should not be nil")
	}

	// Test error messages
	if ErrSensorNotFound.Error() != "sensor not found" {
		t.Errorf("ErrSensorNotFound.Error() = %v, want %v", ErrSensorNotFound.Error(), "sensor not found")
	}

	if ErrSensorAlreadyExists.Error() != "sensor already exists" {
		t.Errorf("ErrSensorAlreadyExists.Error() = %v, want %v", ErrSensorAlreadyExists.Error(), "sensor already exists")
	}

	if ErrInvalidID.Error() != "invalid ID" {
		t.Errorf("ErrInvalidID.Error() = %v, want %v", ErrInvalidID.Error(), "invalid ID")
	}
}

// TestSensorStoreErrors verifies error handling in SensorStore operations.
// Note: Full testing requires MongoDB mocking which is beyond the scope of this quick fix.
// This test serves as a placeholder for future comprehensive store layer testing.
func TestSensorStoreErrors(t *testing.T) {
	t.Parallel()

	// This test documents that comprehensive store testing is needed.
	// For now, we rely on integration tests and the DATA RACE fixes from ADR-0027/28.
	t.Skip("Store layer requires MongoDB mocking for proper unit tests - see future sprint")
}
