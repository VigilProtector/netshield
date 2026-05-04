// Package models contains the data models for NetShield service.
package models

import (
	"testing"
)

// TestPackageConstants verifies that package-level constants are properly defined.
func TestPackageConstants(t *testing.T) {
	t.Parallel()

	// Test FindingContractVersion
	if FindingContractVersion != "2.0" {
		t.Errorf("FindingContractVersion = %v, want %v", FindingContractVersion, "2.0")
	}
}
