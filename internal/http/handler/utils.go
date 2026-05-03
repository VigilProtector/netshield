// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"fmt"
)

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
