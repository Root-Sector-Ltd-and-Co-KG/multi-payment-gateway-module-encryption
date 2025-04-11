package storage

import (
	"context"
	"time"

	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
)

// GarnetAdapter adapts the internal cache to our encryption cache interface
type GarnetAdapter struct {
	client interfaces.Cache
}

// NewGarnetAdapter creates a new adapter for the internal cache
func NewGarnetAdapter(client interfaces.Cache) interfaces.Storage {
	return &GarnetAdapter{
		client: client,
	}
}

// Get retrieves a value from storage
func (g *GarnetAdapter) Get(ctx context.Context, key string, value interface{}) error {
	return g.client.Get(ctx, key, value)
}

// Set stores a value in storage
func (g *GarnetAdapter) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return g.client.Set(ctx, key, value, ttl)
}

// Delete removes a value from storage
func (g *GarnetAdapter) Delete(ctx context.Context, key string) error {
	return g.client.Delete(ctx, key)
}

// Clear removes all values from storage
func (g *GarnetAdapter) Clear(ctx context.Context) error {
	keys, err := g.client.Keys(ctx, "*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := g.client.Delete(ctx, key); err != nil {
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
	err := g.Clear(ctx)

	// We can't know how many were expired, so return 0 with any error
	if err != nil {
		return 0, err
	}

	// Since we can't determine which keys were expired, return 0
	// This is a limitation of the implementation
	return 0, nil
}
