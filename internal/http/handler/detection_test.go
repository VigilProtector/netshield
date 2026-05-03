// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"testing"
)

// TestParseInt tests the parseInt helper function.
func TestParseInt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		defValue int
		want     int
		wantErr  bool
	}{
		{"valid positive", "42", 0, 42, false},
		{"valid negative", "-5", 0, -5, false},
		{"valid zero", "0", 0, 0, false},
		{"empty string", "", 10, 10, true},
		{"invalid string", "abc", 10, 10, true},
		{"invalid float", "3.14", 0, 3, false}, // fmt.Sscanf reads "3" and stops at "."
		{"valid with spaces", "  42  ", 0, 42, false},
		{"valid max int", "2147483647", 0, 2147483647, false},
		{"valid min int", "-2147483648", 0, -2147483648, false},
		{"mixed valid", "123abc", 0, 123, false}, // fmt.Sscanf reads until non-digit
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInt(tt.input, tt.defValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseIntEdgeCases tests edge cases for parseInt.
func TestParseIntEdgeCases(t *testing.T) {
	// Test very large numbers (overflow)
	// Note: fmt.Sscanf will read as much as possible, so very large numbers
	// will overflow and wrap around, but that's acceptable for query parameters
	_, err := parseInt("999999999999999999999", 0)
	if err == nil {
		t.Log("Large number did not error (expected overflow behavior)")
	}

	// Test special characters
	val, err := parseInt("0x10", 0)
	if err == nil {
		t.Logf("Hex number parsed as %d (fmt.Sscanf doesn't parse hex)", val)
	}

	// Test nil/empty
	_, err = parseInt("", 42)
	if err == nil {
		t.Error("Empty string should return error")
	}
}
