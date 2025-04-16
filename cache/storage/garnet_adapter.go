package storage

import (
	"context"
	"time"

	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
)

// GarnetAdapter adapts the internal cache to our encryption cache interface, adding namespacing.
type GarnetAdapter struct {
	client    interfaces.Cache
	keyPrefix string // Namespace prefix for keys
}

// NewGarnetAdapter creates a new adapter for the internal cache with an optional key prefix.
// If keyPrefix is empty, no prefixing is applied.
func NewGarnetAdapter(client interfaces.Cache, keyPrefix string) interfaces.Storage {
	return &GarnetAdapter{
		client:    client,
		keyPrefix: keyPrefix,
	}
}

// prefixedKey returns the key with the prefix prepended.
func (g *GarnetAdapter) prefixedKey(key string) string {
	return g.keyPrefix + key
}

// Get retrieves a value from storage using the prefixed key.
func (g *GarnetAdapter) Get(ctx context.Context, key string, value interface{}) error {
	return g.client.Get(ctx, g.prefixedKey(key), value)
}

// Set stores a value in storage using the prefixed key.
func (g *GarnetAdapter) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return g.client.Set(ctx, g.prefixedKey(key), value, ttl)
}

// Delete removes a value from storage using the prefixed key.
func (g *GarnetAdapter) Delete(ctx context.Context, key string) error {
	return g.client.Delete(ctx, g.prefixedKey(key))
}

// Clear removes all values from storage that match the prefix.
func (g *GarnetAdapter) Clear(ctx context.Context) error {
	// Fetch keys matching the prefix pattern
	pattern := g.keyPrefix + "*"
	keys, err := g.client.Keys(ctx, pattern)
	if err != nil {
		return err
	}
	// Delete only the keys matching the prefix
	for _, key := range keys {
		// Note: The key returned by Keys already includes the prefix
		if err := g.client.Delete(ctx, key); err != nil {
			// Consider logging the error and continuing? Or return immediately?
			// Returning immediately for now.
			return err
		}
	}
	return nil
}

// GetStats returns storage statistics
func (g *GarnetAdapter) GetStats(ctx context.Context) types.CacheStats {
	return types.CacheStats{
		Size:       0, // TODO: Implement size tracking
		LastAccess: time.Now(),
	}
}

// ClearExpiredKeys removes only expired keys and returns the count of removed entries
// For GarnetAdapter, this is implemented as a best-effort operation using Clear
// since we don't have direct access to expiration information
func (g *GarnetAdapter) ClearExpiredKeys(ctx context.Context) (int, error) {
	// We don't have direct access to expiration info in the garnet client,
	// so just call Clear() - this is a limitation of this adapter
	// We don't have direct access to expiration info in the garnet client.
	// This implementation clears all keys matching the prefix, regardless of expiry.
	// It's a best-effort approach based on the Clear method.
	pattern := g.keyPrefix + "*"
	keys, err := g.client.Keys(ctx, pattern)
	if err != nil {
		return 0, err // Return 0 count on error fetching keys
	}

	count := 0
	for _, key := range keys {
		if err := g.client.Delete(ctx, key); err != nil {
			// Log or handle partial failure? Returning error for now.
			return count, err // Return count so far and the error
		}
		count++
	}

	// Return the count of keys that were deleted (matching the prefix)
	return count, nil
}
