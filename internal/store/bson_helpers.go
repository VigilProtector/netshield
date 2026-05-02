// Package store provides the data access layer for NetShield.
// Uses MongoDB for persistence.
package store

import "go.mongodb.org/mongo-driver/v2/bson"

// bsonObjectIDFromHex converts a hex string to bson.ObjectID.
func bsonObjectIDFromHex(hex string) (bson.ObjectID, error) {
	return bson.ObjectIDFromHex(hex)
}
