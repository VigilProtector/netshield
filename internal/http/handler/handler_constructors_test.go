// Package handler provides HTTP handlers for NetShield API.
package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Handler Constructor Tests
// =============================================================================

func TestBoolPtr(t *testing.T) {
	t.Parallel()

	t.Run("true value", func(t *testing.T) {
		t.Parallel()

		ptr := boolPtr(true)
		assert.NotNil(t, ptr)
		assert.True(t, *ptr)
	})

	t.Run("false value", func(t *testing.T) {
		t.Parallel()

		ptr := boolPtr(false)
		assert.NotNil(t, ptr)
		assert.False(t, *ptr)
	})
}

func TestNewDetectionHandler(t *testing.T) {
	t.Parallel()

	// Test with nil service
	handler := NewDetectionHandler(nil)
	assert.NotNil(t, handler)
	assert.Nil(t, handler.service)

	// Test with mock service
	mockService := getMockDetectionService()
	handler = NewDetectionHandler(mockService)
	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.service)
}

func TestNewFindingHandler(t *testing.T) {
	t.Parallel()

	// Test with nil service
	handler := NewFindingHandler(nil)
	assert.NotNil(t, handler)
	assert.Nil(t, handler.service)

	// Test with mock service
	mockService := getMockFindingService()
	handler = NewFindingHandler(mockService)
	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.service)
}

func TestNewRuleSetHandler(t *testing.T) {
	t.Parallel()

	// Test with nil service
	handler := NewRuleSetHandler(nil)
	assert.NotNil(t, handler)
	assert.Nil(t, handler.service)

	// Test with mock service
	mockService := getMockRuleSetService()
	handler = NewRuleSetHandler(mockService)
	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.service)
}

func TestNewSensorHandler(t *testing.T) {
	t.Parallel()

	// Test with nil service
	handler := NewSensorHandler(nil)
	assert.NotNil(t, handler)
	assert.Nil(t, handler.service)

	// Test with mock service
	mockService := getMockSensorService()
	handler = NewSensorHandler(mockService)
	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.service)
}
