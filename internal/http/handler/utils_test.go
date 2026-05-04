// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseInt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		def      int
		expected int
		expectErr bool
	}{
		{"valid positive", "42", 0, 42, false},
		{"valid negative", "-5", 0, -5, false},
		{"valid zero", "0", 0, 0, false},
		{"empty string", "", 10, 10, true},
		{"invalid string", "abc", 10, 10, true},
		{"whitespace", " 123 ", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseInt(tt.input, tt.def)
			assert.Equal(t, tt.expected, result)
			if tt.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestParseAndValidateLimit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		def      int
		expected int
		expectErr bool
	}{
		{"valid within max", "50", 10, 50, false},
		{"valid at max", "1000", 10, 1000, false},
		{"above max", "1500", 10, 1000, false},
		{"empty string", "", 50, 50, true},
		{"invalid string", "abc", 50, 50, true},
		{"negative", "-5", 10, 1, false}, // negative gets clamped to 1
		{"zero", "0", 10, 1, false},     // zero gets clamped to 1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAndValidateLimit(tt.input, tt.def)
			assert.Equal(t, tt.expected, result)
			if tt.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestParseAndValidateOffset(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		def      int
		expected int
		expectErr bool
	}{
		{"valid positive", "42", 0, 42, false},
		{"valid zero", "0", 0, 0, false},
		{"empty string", "", 10, 10, true},
		{"invalid string", "abc", 10, 10, true},
		{"negative", "-5", 10, 0, false}, // negative gets clamped to 0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAndValidateOffset(tt.input, tt.def)
			assert.Equal(t, tt.expected, result)
			if tt.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
