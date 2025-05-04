package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Constants for cache management
const (
	// Cache key prefixes
	cacheKeyPrefixDEKInfo = "dek_info"
	cacheKeyPrefixDEK     = "dek"

	// Default TTL values
	defaultCacheTTL = 15 * time.Minute
)

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

// MongoDBStore implements DEK storage using MongoDB
type MongoDBStore struct {
	db       *mongo.Database
	cache    sync.Map
	cacheTTL time.Duration
}

// NewMongoDBStore creates a new MongoDB DEK store
func NewMongoDBStore(db *mongo.Database) interfaces.DEKStore {
	return &MongoDBStore{
		db:       db,
		cacheTTL: defaultCacheTTL,
	}
}

// getCacheKey generates a cache key for the store
func (s *MongoDBStore) getCacheKey(scope, orgID string) string {
	if scope == "system" {
		return fmt.Sprintf("%s:system", cacheKeyPrefixDEKInfo)
	}
	return fmt.Sprintf("%s:org:%s", cacheKeyPrefixDEKInfo, orgID)
}

// StoreDEK stores a DEK in the appropriate document based on scope
func (s *MongoDBStore) StoreDEK(ctx context.Context, info *types.DEKInfo, scope string, orgID string) error {
	// +++ Add Logging +++
	log.Info().
		Str("method", "StoreDEK").
		Str("scope", scope).
		Str("orgID", orgID). // Log the received orgID string
		Msg("Entering StoreDEK")
	// +++ End Logging +++

	// Update timestamps
	info.UpdatedAt = time.Now().UTC()
	if info.CreatedAt.IsZero() {
		info.CreatedAt = info.UpdatedAt
	}

	var collection string
	var filter bson.M

	if scope == "system" {
		collection = "system"
		filter = bson.M{"_id": "1"}
	} else if scope == "organization" {
		// +++ Add Logging Inside Scope Check +++
		log.Info().
			Str("method", "StoreDEK").
			Str("scope", scope).
			Str("orgID", orgID).
			Msg("Processing organization scope")
		// +++ End Logging +++
		if orgID == "" {
			// +++ Add Logging Before Error +++
			log.Error().
				Str("method", "StoreDEK").
				Str("scope", scope).
				Msg("orgID is empty, returning error")
			// +++ End Logging +++
			return fmt.Errorf("organization ID is required for organization scope")
		}
		collection = "organizations"
		// Convert orgID string to ObjectID for filtering
		objID, err := bson.ObjectIDFromHex(orgID)
		if err != nil {
			return fmt.Errorf("invalid organization ID format: %w", err)
		}
		filter = bson.M{"_id": objID}
	} else {
		return fmt.Errorf("invalid scope: %s", scope)
	}

	// Store DEK in document
	_, err := s.db.Collection(collection).UpdateOne(
		ctx,
		filter,
		bson.M{
			"$set": bson.M{
				"dek":       info,
				"updatedAt": info.UpdatedAt,
			},
		},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		return fmt.Errorf("failed to store DEK: %w", err)
	}

	// Update cache with cacheEntry
	cacheKey := s.getCacheKey(scope, orgID)
	s.cache.Store(cacheKey, &cacheEntry{
		value:     info,
		expiresAt: time.Now().Add(s.cacheTTL),
	})
	log.Debug().
		Str("scope", scope).
		Str("orgID", orgID).
		Str("cacheKey", cacheKey).
		Int("version", info.Version).
		Int("numVersions", len(info.Versions)).
		Msg("DEK info cached after store")

	return nil
}

// GetDEK retrieves a DEK from the appropriate document
func (s *MongoDBStore) GetDEK(ctx context.Context, id string, scope string) (*types.DEKInfo, error) {
	var collection string
	var filter bson.M

	if scope == "system" {
		collection = "system"
		filter = bson.M{"_id": "1"}
	} else if scope == "organization" {
		collection = "organizations"
		// Convert id string to ObjectID for filtering
		objID, err := bson.ObjectIDFromHex(id)
		if err != nil {
			return nil, fmt.Errorf("invalid organization id format: %w", err)
		}
		filter = bson.M{"_id": objID}
	} else {
		return nil, fmt.Errorf("invalid scope: %s", scope)
	}

	var result struct {
		DEK *types.DEKInfo `bson:"dek"`
	}
	err := s.db.Collection(collection).FindOne(ctx, filter, options.FindOne().SetProjection(bson.M{"dek": 1})).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // Return nil, nil if not found
		}
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}

	return result.DEK, nil
}

// GetActiveDEK retrieves the active DEK for the given scope
func (s *MongoDBStore) GetActiveDEK(ctx context.Context, scope string, orgID string) (*types.DEKInfo, error) {
	cacheKey := s.getCacheKey(scope, orgID)

	// Try cache first
	if cached, ok := s.cache.Load(cacheKey); ok {
		if entry, ok := cached.(*cacheEntry); ok && time.Now().Before(entry.expiresAt) {
			if dekInfo, ok := entry.value.(*types.DEKInfo); ok {
				log.Debug().
					Str("scope", scope).
					Str("orgID", orgID).
					Str("cacheKey", cacheKey).
					Bool("hasVersions", len(dekInfo.Versions) > 0).
					Int("version", dekInfo.Version).
					Msg("Using cached DEK info")
				return dekInfo, nil
			}
		} else {
			// Remove expired entry
			s.cache.Delete(cacheKey)
		}
	}

	// Fetch from DB if not cached or expired
	dekInfo, err := s.GetDEK(ctx, orgID, scope) // Use GetDEK which handles scope and ID conversion
	if err != nil {
		return nil, err // Propagate DB error
	}
	if dekInfo == nil {
		log.Debug().Str("scope", scope).Str("orgID", orgID).Msg("No DEK found in DB")
		return nil, nil // Not found
	}

	// Check if active
	if !dekInfo.Active {
		log.Debug().
			Str("dekId", dekInfo.Id). // Use Id
			Int("version", dekInfo.Version).
			Msg("Found DEK but it is not active")
		return nil, nil // Found but not active
	}

	if len(dekInfo.Versions) == 0 {
		log.Error().
			Str("dekId", dekInfo.Id). // Use Id
			Msg("DEK has no versions")
		return nil, fmt.Errorf("DEK has no versions")
	}

	// Cache the result
	s.cache.Store(cacheKey, &cacheEntry{
		value:     dekInfo,
		expiresAt: time.Now().Add(s.cacheTTL),
	})
	log.Debug().
		Str("scope", scope).
		Str("orgID", orgID).
		Str("cacheKey", cacheKey).
		Int("version", dekInfo.Version).
		Int("numVersions", len(dekInfo.Versions)).
		Msg("DEK info cached after fetch")

	return dekInfo, nil
}

// ListDEKs lists all DEKs for the given scope
func (s *MongoDBStore) ListDEKs(ctx context.Context, scope string) ([]*types.DEKInfo, error) {
	var collection string
	var filter bson.M

	if scope == "system" {
		collection = "system"
		filter = bson.M{"dek": bson.M{"$exists": true}} // Single system document with DEK
	} else if scope == "organization" {
		collection = "organizations"
		filter = bson.M{"dek": bson.M{"$exists": true}} // All organization documents with DEK
	} else {
		return nil, fmt.Errorf("invalid scope: %s", scope)
	}

	cursor, err := s.db.Collection(collection).Find(ctx, filter, options.Find().SetProjection(bson.M{"dek": 1}))
	if err != nil {
		return nil, fmt.Errorf("failed to list DEKs: %w", err)
	}
	defer cursor.Close(ctx)

	var results []struct {
		DEK *types.DEKInfo `bson:"dek"`
	}
	if err := cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode DEKs: %w", err)
	}

	deks := make([]*types.DEKInfo, 0, len(results))
	for _, result := range results {
		if result.DEK != nil { // Ensure DEK is not nil before appending
			deks = append(deks, result.DEK)
		}
	}

	return deks, nil
}

// DeleteDEK deletes a DEK from the appropriate document
func (s *MongoDBStore) DeleteDEK(ctx context.Context, id string, scope string) error {
	var collection string
	var filter bson.M

	if scope == "system" {
		collection = "system"
		filter = bson.M{"_id": "1"} // Target the specific system document
	} else if scope == "organization" {
		collection = "organizations"
		// Convert id string to ObjectID for filtering
		objID, err := bson.ObjectIDFromHex(id)
		if err != nil {
			return fmt.Errorf("invalid organization id format: %w", err)
		}
		filter = bson.M{"_id": objID}
	} else {
		return fmt.Errorf("invalid scope: %s", scope)
	}

	_, err := s.db.Collection(collection).UpdateOne(
		ctx,
		filter,
		bson.M{"$unset": bson.M{"dek": ""}},
	)
	if err != nil {
		return fmt.Errorf("failed to delete DEK: %w", err)
	}

	// Clear cache
	cacheKey := s.getCacheKey(scope, id)
	s.cache.Delete(cacheKey)
	log.Debug().
		Str("scope", scope).
		Str("id", id).
		Str("cacheKey", cacheKey).
		Msg("DEK info removed from cache")

	return nil
}
