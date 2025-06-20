package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/root-sector-ltd-and-co-kg/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector-ltd-and-co-kg/multi-payment-gateway-module-encryption/types"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	globalAdapter *MemoryAdapter
	adapterMu     sync.RWMutex
)

// MemoryAdapter implements the Storage interface with in-memory storage
type MemoryAdapter struct {
	mu          sync.RWMutex
	data        map[string]*types.CacheEntry
	ttl         map[string]time.Time
	lastAccess  map[string]time.Time
	stats       types.CacheStats
	logger      *zerolog.Logger
	maxSize     int
	evictCh     chan struct{}
	done        chan struct{}
	accessOrder []string // LRU tracking
}

// NewMemoryAdapter creates a new in-memory storage adapter
func NewMemoryAdapter() interfaces.Storage {
	adapterMu.Lock()
	defer adapterMu.Unlock()

	if globalAdapter != nil {
		log.Trace().Msg("Reusing existing memory cache adapter")
		return globalAdapter
	}

	logger := log.With().Str("component", "memory_cache").Logger()

	adapter := &MemoryAdapter{
		data:        make(map[string]*types.CacheEntry),
		ttl:         make(map[string]time.Time),
		lastAccess:  make(map[string]time.Time),
		accessOrder: make([]string, 0, 100), // Pre-allocate for better performance
		maxSize:     1000,                   // Default max size
		evictCh:     make(chan struct{}, 1),
		done:        make(chan struct{}),
		stats: types.CacheStats{
			LastAccess:  time.Now().UTC(),
			LastUpdated: time.Now().UTC(),
			LastPurged:  time.Now().UTC(),
		},
		logger: &logger,
	}

	// Start background cleanup routine
	go adapter.startEvictionRoutine()

	logger.Debug().
		Int("max_size", adapter.maxSize).
		Msg("Memory cache adapter initialized")

	globalAdapter = adapter
	return adapter
}

// startEvictionRoutine starts a background routine for cache eviction
func (a *MemoryAdapter) startEvictionRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.evictExpired()
		case <-a.evictCh:
			a.evictLRU()
		case <-a.done:
			return
		}
	}
}

// evictExpired removes expired entries
func (a *MemoryAdapter) evictExpired() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now().UTC()
	var expired []string

	for key, expiry := range a.ttl {
		if now.After(expiry) {
			expired = append(expired, key)
		}
	}

	if len(expired) > 0 {
		for _, key := range expired {
			a.removeKey(key)
		}

		a.logger.Debug().
			Int("expired_count", len(expired)).
			Time("purged_at", a.stats.LastPurged).
			Msg("Expired entries cleaned up")
	}
}

// evictLRU removes least recently used entries when cache is full
func (a *MemoryAdapter) evictLRU() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// If we're under the limit, no need to evict
	if len(a.data) <= a.maxSize {
		return
	}

	// Calculate how many entries to evict (20% of max size)
	toEvict := (len(a.data) - a.maxSize) + (a.maxSize / 5)
	if toEvict <= 0 {
		return
	}

	// Sort entries by last access time
	type entry struct {
		key      string
		lastUsed time.Time
	}
	entries := make([]entry, 0, len(a.lastAccess))
	for k, t := range a.lastAccess {
		entries = append(entries, entry{k, t})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastUsed.Before(entries[j].lastUsed)
	})

	// Evict oldest entries
	evicted := 0
	for _, e := range entries {
		if evicted >= toEvict {
			break
		}
		a.removeKey(e.key)
		evicted++
	}

	a.logger.Debug().
		Int("evicted_count", evicted).
		Int("current_size", len(a.data)).
		Msg("LRU eviction completed")
}

// removeKey removes a key and securely wipes its data
func (a *MemoryAdapter) removeKey(key string) {
	if entry, exists := a.data[key]; exists {
		// Securely wipe the entry
		entry.Clear()
	}
	delete(a.data, key)
	delete(a.ttl, key)
	delete(a.lastAccess, key)

	// Remove from access order
	for i, k := range a.accessOrder {
		if k == key {
			a.accessOrder = append(a.accessOrder[:i], a.accessOrder[i+1:]...)
			break
		}
	}

	a.stats.Size = len(a.data)
	a.stats.LastUpdated = time.Now().UTC()
}

// updateAccessTime updates the last access time for a key
// IMPORTANT: Caller MUST hold a.mu write lock when calling this function
func (a *MemoryAdapter) updateAccessTime(key string) {
	now := time.Now().UTC()
	a.lastAccess[key] = now

	// Update access order
	for i, k := range a.accessOrder {
		if k == key {
			// Move to end (most recently used)
			a.accessOrder = append(append(a.accessOrder[:i], a.accessOrder[i+1:]...), key)
			return
		}
	}
	// If key not found, append it
	a.accessOrder = append(a.accessOrder, key)
}

// Get retrieves a value from storage with optimized locking
func (a *MemoryAdapter) Get(ctx context.Context, key string, value interface{}) error {
	if a == nil {
		return errors.New("cache: adapter is nil")
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	a.mu.RLock()

	// Check if key exists
	entry, exists := a.data[key]
	if !exists {
		a.mu.RUnlock()
		a.stats.Misses++
		a.stats.LastAccess = time.Now().UTC()
		a.logger.Trace().
			Str("key", key).
			Msg("Cache entry not found")
		return errors.New("cache: key not found")
	}

	// Check if key has expired
	expiry, hasExpiry := a.ttl[key]
	if hasExpiry && time.Now().UTC().After(expiry) {
		// Expired entry, remove it
		a.mu.RUnlock()

		// Get a write lock to remove the expired entry
		a.mu.Lock()
		// Check again under write lock (could have changed)
		if expiry, hasExpiry := a.ttl[key]; hasExpiry && time.Now().UTC().After(expiry) {
			delete(a.data, key)
			delete(a.ttl, key)
			delete(a.lastAccess, key)
		}
		a.mu.Unlock()

		a.stats.Misses++
		a.stats.LastAccess = time.Now().UTC()
		a.logger.Trace().
			Str("key", key).
			Time("expired_at", expiry).
			Msg("Cache entry expired")
		return errors.New("cache: key not found")
	}

	// Need to release read lock and acquire write lock to update access time safely
	a.mu.RUnlock()

	// Acquire write lock for updating access time
	a.mu.Lock()

	// Need to check again if the key still exists after acquiring write lock
	entry, exists = a.data[key]
	if !exists {
		a.mu.Unlock()
		a.stats.Misses++
		a.stats.LastAccess = time.Now().UTC()
		return errors.New("cache: key not found")
	}

	// Update access time under write lock
	a.updateAccessTime(key)
	a.mu.Unlock()

	// Copy entry to output value
	if v, ok := value.(*types.CacheEntry); ok {
		v.Value = entry.Value
		v.Version = entry.Version
	}

	a.stats.Hits++
	a.stats.LastAccess = time.Now().UTC()
	a.logger.Trace().
		Str("key", key).
		Msg("Cache hit")

	return nil
}

// Set stores a value in storage
func (a *MemoryAdapter) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if a == nil {
		return errors.New("cache: adapter is nil")
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check size and trigger eviction if needed
	if len(a.data) >= a.maxSize {
		select {
		case a.evictCh <- struct{}{}:
		default:
		}
	}

	// If key exists, securely wipe old data
	if oldEntry, exists := a.data[key]; exists {
		oldEntry.Clear()
	}

	// Store new entry with secure bytes
	if entry, ok := value.(*types.CacheEntry); ok {
		a.data[key] = entry
	} else {
		return fmt.Errorf("invalid value type: expected *types.CacheEntry")
	}

	if ttl > 0 {
		a.ttl[key] = time.Now().UTC().Add(ttl)
	}

	// Update access time - we already hold the lock
	a.updateAccessTime(key)

	// Update stats
	a.stats.Size = len(a.data)
	a.stats.LastUpdated = time.Now().UTC()
	a.logger.Trace().
		Str("key", key).
		Int("ttlSeconds", int(ttl.Seconds())).
		Msg("Cache entry stored")

	return nil
}

// Delete removes a value from storage
func (a *MemoryAdapter) Delete(ctx context.Context, key string) error {
	if a == nil {
		return errors.New("cache: adapter is nil")
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.data[key]; exists {
		a.removeKey(key)
		a.logger.Debug().
			Str("key", key).
			Msg("Cache entry deleted")
	}
	return nil
}

// Clear removes all values from storage
func (a *MemoryAdapter) Clear(ctx context.Context) error {
	if a == nil {
		return errors.New("cache: adapter is nil")
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Securely clear all entries
	for _, entry := range a.data {
		entry.Clear()
	}

	// Clear all maps
	a.data = make(map[string]*types.CacheEntry)
	a.ttl = make(map[string]time.Time)
	a.lastAccess = make(map[string]time.Time)
	a.accessOrder = make([]string, 0)

	// Update stats
	a.stats.Size = 0
	a.stats.LastUpdated = time.Now().UTC()
	a.logger.Debug().Msg("Cache cleared")

	return nil
}

// GetStats returns storage statistics
func (a *MemoryAdapter) GetStats(ctx context.Context) types.CacheStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stats
}

// Shutdown performs graceful shutdown with secure cleanup
func (a *MemoryAdapter) Shutdown() error {
	close(a.done)
	return a.Clear(context.Background())
}

// GetTTLMap returns a copy of the TTL map for inspection
func (a *MemoryAdapter) GetTTLMap() map[string]time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Create a copy to prevent external modification
	ttlCopy := make(map[string]time.Time, len(a.ttl))
	for k, v := range a.ttl {
		ttlCopy[k] = v
	}
	return ttlCopy
}

// ClearExpiredKeys removes only expired keys and returns the count of removed entries
func (a *MemoryAdapter) ClearExpiredKeys(ctx context.Context) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now().UTC()
	var expired []string

	// Find expired keys
	for key, expiry := range a.ttl {
		if now.After(expiry) {
			expired = append(expired, key)
		}
	}

	// Remove expired keys
	for _, key := range expired {
		a.removeKey(key)
	}

	// Log if we cleared a significant number
	if len(expired) > 0 {
		a.logger.Debug().
			Int("expired_count", len(expired)).
			Time("purged_at", a.stats.LastPurged).
			Msg("Expired entries cleaned up")
	}

	return len(expired), nil
}
