// Package store provides the data access layer for NetShield.
package store

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestBsonObjectIDFromHex(t *testing.T) {
	t.Parallel()

	t.Run("valid hex string", func(t *testing.T) {
		t.Parallel()

		hex := "507f1f77bcf86cd799439011"
		got, err := bsonObjectIDFromHex(hex)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected, err := bson.ObjectIDFromHex(hex)
		if err != nil {
			t.Fatalf("failed to create expected ObjectID: %v", err)
		}

		if got != expected {
			t.Errorf("bsonObjectIDFromHex(%q) = %v, want %v", hex, got, expected)
		}
	})

	t.Run("empty string", func(t *testing.T) {
		t.Parallel()

		got, err := bsonObjectIDFromHex("")
		if err == nil {
			t.Errorf("expected error for empty string, got nil")
		}
		if got != (bson.ObjectID{}) {
			t.Errorf("expected zero ObjectID for empty string, got %v", got)
		}
	})

	t.Run("invalid hex string", func(t *testing.T) {
		t.Parallel()

		got, err := bsonObjectIDFromHex("invalid")
		if err == nil {
			t.Errorf("expected error for invalid hex string, got nil")
		}
		if got != (bson.ObjectID{}) {
			t.Errorf("expected zero ObjectID for invalid hex string, got %v", got)
		}
	})

	t.Run("short hex string", func(t *testing.T) {
		t.Parallel()

		got, err := bsonObjectIDFromHex("123")
		if err == nil {
			t.Errorf("expected error for short hex string, got nil")
		}
		if got != (bson.ObjectID{}) {
			t.Errorf("expected zero ObjectID for short hex string, got %v", got)
		}
	})
}
