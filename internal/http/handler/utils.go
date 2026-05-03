// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"fmt"
)

// MaxLimit is the maximum allowed limit for pagination.
const MaxLimit = 1000

// parseInt is a helper function to parse integer query parameters.
// Returns defaultValue if parsing fails.
func parseInt(s string, defaultValue int) (int, error) {
	var val int

	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		return defaultValue, err
	}

	return val, nil
}

// parseAndValidateLimit parses limit query parameter and ensures it does not exceed MaxLimit.
// Returns the parsed limit or defaultValue if parsing fails.
// Enforces maximum limit of MaxLimit (1000) for pagination.
func parseAndValidateLimit(s string, defaultValue int) (int, error) {
	limit, err := parseInt(s, defaultValue)
	if err != nil {
		return defaultValue, err
	}

	// Enforce maximum limit
	if limit > MaxLimit {
		limit = MaxLimit
	}

	// Ensure limit is at least 1
	if limit < 1 {
		limit = 1
	}

	return limit, nil
}

// parseAndValidateOffset parses offset query parameter.
// Returns the parsed offset or defaultValue if parsing fails.
// Ensures offset is non-negative.
func parseAndValidateOffset(s string, defaultValue int) (int, error) {
	offset, err := parseInt(s, defaultValue)
	if err != nil {
		return defaultValue, err
	}

	// Ensure offset is non-negative
	if offset < 0 {
		offset = 0
	}

	return offset, nil
}
