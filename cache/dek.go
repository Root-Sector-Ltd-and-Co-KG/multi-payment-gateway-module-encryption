// Package cache provides caching functionality for encryption operations.
package cache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// CacheMetrics holds cache performance metrics for monitoring and diagnostics.
type CacheMetrics struct {
	HitRate        float64       `json:"hit_rate"`        // Percentage of successful cache hits
	MissRate       float64       `json:"miss_rate"`       // Percentage of cache misses
	EvictionCount  int64         `json:"eviction_count"`  // Number of entries evicted from cache
	AverageLatency time.Duration `json:"average_latency"` // Average time for cache operations
	Size           int           `json:"size"`            // Current number of entries in cache
	Uptime         time.Duration `json:"uptime"`          // Time since cache initialization
	MemoryUsage    int64         `json:"memory_usage"`    // Estimated memory usage in bytes
	ErrorRate      float64       `json:"error_rate"`      // Percentage of failed operations
}

// DEKCache implements the types.Cache interface for Data Encryption Key (DEK) caching.
// It provides thread-safe caching with circuit breaker pattern and request-level caching
// to optimize performance and handle failures gracefully.
type DEKCache struct {
	config        *types.CacheConfig // Configuration for cache behavior
	store         interfaces.Storage // Underlying storage implementation
	mu            sync.RWMutex       // Mutex for thread-safe operations
	stats         types.CacheStats   // Cache statistics
	logger        *zerolog.Logger    // Structured logger
	cleanupTicker *time.Ticker       // Ticker for periodic cleanup
	done          chan struct{}      // Channel for shutdown signaling
	startTime     time.Time          // Cache initialization time
	evictionCount int64              // Number of evicted entries
	totalLatency  time.Duration      // Total operation latency
	errorCount    int64              // Total error count
	totalOps      int64              // Total operations count

	// Circuit breaker fields
	consecutiveErrors int32        // Count of consecutive errors
	breakerTripped    bool         // Circuit breaker state
	breakerResetTime  time.Time    // Time when breaker should reset
	breakerMu         sync.RWMutex // Mutex for circuit breaker operations

	// Request-level cache fields
	requestCache     map[string]*types.CacheEntry // Short-lived request cache
	requestCacheMu   sync.RWMutex                 // Mutex for request cache
	requestCacheTTL  time.Duration                // TTL for request cache entries
	requestCacheTime time.Time                    // Last request cache cleanup time
}

// Constants for circuit breaker configuration
const (
	maxConsecutiveErrors = 10               // Increased from 5 to 10 to be less sensitive
	breakerResetTimeout  = 1 * time.Minute  // Time before breaker auto-resets
	breakerHalfOpen      = 30 * time.Second // Time before allowing a test request
)

// NewDEKCache creates a new DEK cache instance with the provided configuration and storage backend.
// It initializes the cache with proper defaults if config is invalid and starts background
// cleanup routines.
func NewDEKCache(config *types.CacheConfig, store interfaces.Storage) types.Cache {
	logger := log.With().Str("component", "dek_cache").Logger()

	if err := validateCacheConfig(config); err != nil {
		logger.Warn().Err(err).Msg("Invalid cache config, using defaults")
		config = getDefaultConfig()
	}

	cache := &DEKCache{
		config:    config,
		store:     store,
		logger:    &logger,
		done:      make(chan struct{}),
		startTime: time.Now().UTC(),
		stats: types.CacheStats{
			LastPurged:  time.Now().UTC(),
			LastAccess:  time.Now().UTC(),
			LastUpdated: time.Now().UTC(),
		},
		requestCache:     make(map[string]*types.CacheEntry),
		requestCacheTTL:  5 * time.Second, // Short TTL for request-level cache
		requestCacheTime: time.Now(),
	}

	// Start background cleanup routines
	cache.startCleanupRoutine()
	go cache.startRequestCacheCleanup()

	logger.Info().
		Bool("enabled", config.Enabled).
		Dur("ttl", config.GetEffectiveTTL()).
		Msg("DEK cache initialized")

	return cache
}

// validateCacheConfig validates the provided cache configuration.
// Returns an error if the configuration is invalid.
func validateCacheConfig(config *types.CacheConfig) error {
	if config == nil {
		return fmt.Errorf("cache config cannot be nil")
	}

	// TTL validation is handled by GetEffectiveTTL
	return nil
}

// getDefaultConfig returns a default cache configuration with reasonable defaults.
func getDefaultConfig() *types.CacheConfig {
	return &types.CacheConfig{
		Enabled: true,
		TTL:     types.DefaultCacheTTLMinutes,
	}
}

// startCleanupRoutine starts a background routine that periodically cleans up expired entries.
// The cleanup interval is set to 15 minutes since DEK cache entries are typically long-lived.
func (c *DEKCache) startCleanupRoutine() {
	// Run cleanup every 15 minutes instead of every minute since DEK cache entries are long-lived
	c.cleanupTicker = time.NewTicker(15 * time.Minute)

	go func() {
		for {
			select {
			case <-c.cleanupTicker.C:
				if expired := c.cleanup(); expired > 0 {
					c.logger.Debug().
						Int("expired", expired).
						Int("size", c.stats.Size).
						Time("purged_at", c.stats.LastPurged).
						Msg("Cache cleanup completed")
				}
			case <-c.done:
				return
			}
		}
	}()
}

// cleanup removes expired entries from the cache and returns the number of expired entries.
// This function is called periodically by the cleanup routine.
func (c *DEKCache) cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	before := c.stats.Size

	// Clear expired keys using the interface method
	expiredCount, err := c.store.ClearExpiredKeys(context.Background())
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to cleanup expired cache entries")
		return 0
	}

	// Update statistics
	atomic.AddInt64(&c.evictionCount, int64(expiredCount))

	c.stats.LastPurged = time.Now().UTC()
	c.stats.Size = before - expiredCount

	return expiredCount
}

// Enable activates the cache for use.
func (c *DEKCache) Enable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Enabled = true
}

// Disable deactivates the cache and clears all entries.
func (c *DEKCache) Disable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Enabled = false
	c.Clear()
}

// IsEnabled returns whether the cache is currently enabled.
func (c *DEKCache) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Enabled
}

// Clear removes all entries from the cache and resets statistics.
func (c *DEKCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.store.Clear(context.Background()); err != nil {
		c.logger.Error().
			Err(err).
			Msg("Failed to clear cache")
		return
	}

	// Reset stats
	c.stats = types.CacheStats{
		LastPurged:  time.Now().UTC(),
		LastAccess:  time.Now().UTC(),
		LastUpdated: time.Now().UTC(),
	}

	// Only log successful clear at debug level
	c.logger.Debug().Msg("Cache cleared successfully")
}

// checkCircuitBreaker checks if the circuit breaker is currently tripped.
// Returns true if the breaker is tripped and hasn't timed out.
func (c *DEKCache) checkCircuitBreaker() bool {
	c.breakerMu.RLock()

	// If breaker is not tripped, return immediately
	if !c.breakerTripped {
		c.breakerMu.RUnlock()
		return false
	}

	now := time.Now()

	// If we've passed the reset timeout, fully reset the breaker
	if now.After(c.breakerResetTime.Add(breakerResetTimeout)) {
		c.breakerMu.RUnlock() // Release read lock before acquiring write lock
		c.resetCircuitBreaker()
		return false
	}

	// If we're in half-open state, allow a test request
	if now.After(c.breakerResetTime.Add(breakerHalfOpen)) {
		// Release read lock before test operation
		c.breakerMu.RUnlock()

		if c.testCacheOperation() {
			c.resetCircuitBreaker()
			return false
		}

		// Re-acquire read lock for the final state check
		c.breakerMu.RLock()
		isBreakerTripped := c.breakerTripped
		c.breakerMu.RUnlock()

		return isBreakerTripped
	}

	// Release lock before returning
	isBreakerTripped := c.breakerTripped
	c.breakerMu.RUnlock()

	return isBreakerTripped
}

// testCacheOperation attempts a test operation to see if the cache is healthy
func (c *DEKCache) testCacheOperation() bool {
	// Try a simple cache operation
	testKey := fmt.Sprintf("test_key_%s", uuid.New().String())
	testData := []byte("test")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.store.Set(ctx, testKey, &types.CacheEntry{
		Value:   types.NewSecureBytes(testData),
		Version: 1,
	}, 5*time.Second)

	if err != nil {
		c.logger.Debug().Err(err).Msg("Cache test operation failed")
		return false
	}

	// Clean up test key
	_ = c.store.Delete(ctx, testKey)
	return true
}

// tripCircuitBreaker activates the circuit breaker after too many consecutive errors
func (c *DEKCache) tripCircuitBreaker() {
	c.breakerMu.Lock()
	defer c.breakerMu.Unlock()

	// Double check we're not already tripped
	if c.breakerTripped {
		return
	}

	c.breakerTripped = true
	c.breakerResetTime = time.Now()
	atomic.StoreInt32(&c.consecutiveErrors, 0)

	c.logger.Warn().
		Time("reset_time", c.breakerResetTime).
		Dur("half_open_after", breakerHalfOpen).
		Dur("full_reset_after", breakerResetTimeout).
		Msg("Circuit breaker tripped")
}

// resetCircuitBreaker resets the circuit breaker state and error count
func (c *DEKCache) resetCircuitBreaker() {
	c.breakerMu.Lock()
	defer c.breakerMu.Unlock()

	if !c.breakerTripped {
		return
	}

	c.breakerTripped = false
	atomic.StoreInt32(&c.consecutiveErrors, 0)

	c.logger.Info().
		Time("last_tripped", c.breakerResetTime).
		Msg("Circuit breaker reset")
}

// recordError records a cache operation error and potentially trips the circuit breaker
func (c *DEKCache) recordError() {
	atomic.AddInt64(&c.errorCount, 1)
	errors := atomic.AddInt32(&c.consecutiveErrors, 1)

	// Only trip breaker if we're not already in tripped state
	c.breakerMu.RLock()
	alreadyTripped := c.breakerTripped
	c.breakerMu.RUnlock()

	if !alreadyTripped && errors >= maxConsecutiveErrors {
		c.tripCircuitBreaker()
	}
}

// recordSuccess records a successful cache operation and resets the consecutive error count.
func (c *DEKCache) recordSuccess() {
	atomic.StoreInt32(&c.consecutiveErrors, 0)
}

// Get retrieves a value from the cache by key.
// Returns the value, its version, and a boolean indicating if the value was found.
// Implements circuit breaker pattern to prevent cascade failures.
func (c *DEKCache) Get(ctx context.Context, key string) (*types.SecureBytes, int, bool) {
	if !c.IsEnabled() {
		return nil, 0, false
	}

	// Check circuit breaker
	if c.checkCircuitBreaker() {
		c.logger.Debug().Msg("Cache access blocked by circuit breaker")
		return nil, 0, false
	}

	atomic.AddInt64(&c.totalOps, 1)
	start := time.Now()

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, 0, false
	default:
	}

	// --- Request Cache Check ---
	c.requestCacheMu.RLock()

	reqEntry, reqFound := c.requestCache[key] // Perform the check under the same lock
	// log.Debug().Str("key", key).Bool("found", reqFound).Msg("DEKCache.Get: Request cache lookup result") // DIAGNOSTIC LOG REMOVED
	// Check only if found. Expiry is handled by the cleanup routine.
	if reqFound {
		// Found in request cache
		c.requestCacheMu.RUnlock() // Release read lock before returning
		c.stats.Hits++             // Count as a hit
		c.stats.LastAccess = time.Now().UTC()
		c.logger.Trace().Str("key", key).Msg("Request cache hit") // Reverted to Trace level
		c.recordSuccess()                                         // Record success for circuit breaker
		c.totalLatency += time.Since(start)
		return reqEntry.Value, reqEntry.Version, true
	}
	c.requestCacheMu.RUnlock() // Release read lock if missed or expired
	// --- End Request Cache Check ---

	// If not found in request cache, check persistent store
	c.mu.RLock() // Lock for persistent store access

	var entry types.CacheEntry
	err := c.store.Get(ctx, key, &entry)
	if err != nil {
		c.mu.RUnlock() // Unlock persistent store mutex on error
		c.stats.Misses++
		c.stats.LastAccess = time.Now().UTC()
		c.logger.Trace().
			Str("key", key).
			Err(err).
			Msg("Persistent cache miss") // Clarify log message
		c.recordError()
		return nil, 0, false
	}
	// Persistent store hit, unlock read lock before potentially populating request cache
	c.mu.RUnlock()

	// Validate entry
	if entry.Value == nil || len(entry.Value.Get()) == 0 {
		c.logger.Error().
			Str("key", key).
			Msg("Invalid cache entry: empty or nil value")
		return nil, 0, false
	}

	c.stats.Hits++ // Count persistent store hit
	c.stats.LastAccess = time.Now().UTC()

	// --- Populate Request Cache on Persistent Hit ---
	c.requestCacheMu.Lock()
	// Check if another goroutine populated it while we waited for the lock
	_, alreadyExists := c.requestCache[key]
	if !alreadyExists {
		// Add a copy to avoid race conditions if entry is modified elsewhere
		// No Expiry field needed here, cleanup routine handles it.
		reqCacheEntry := &types.CacheEntry{
			Value:   entry.Value, // SecureBytes is already a copy/pointer
			Version: entry.Version,
		}
		c.requestCache[key] = reqCacheEntry
		// c.logger.Trace().Str("key", key).Msg("Populated request cache from persistent hit") // Removed diagnostic log
	}
	c.requestCacheMu.Unlock()
	// --- End Populate Request Cache ---

	c.logger.Trace().
		Str("key", key).
		Int("version", entry.Version).
		Int("valueSize", len(entry.Value.Get())).
		Msg("Persistent cache hit")

	c.recordSuccess()
	c.totalLatency += time.Since(start)
	return entry.Value, entry.Version, true
}

// Set adds or updates a value in the cache with the specified key and version.
// The value is stored as SecureBytes for enhanced security.
func (c *DEKCache) Set(ctx context.Context, key string, value []byte, version int) {
	if !c.IsEnabled() || len(value) == 0 {
		return
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return
	default:
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Create secure bytes from value
	secureValue := types.NewSecureBytes(value)
	if secureValue == nil || len(secureValue.Get()) == 0 {
		log.Error().
			Str("key", key).
			Msg("Failed to create secure bytes")
		return
	}

	entry := &types.CacheEntry{
		Value:   secureValue,
		Version: version,
	}

	err := c.store.Set(ctx, key, entry, c.config.GetEffectiveTTL())
	if err != nil {
		log.Error().
			Str("key", key).
			Err(err).
			Msg("Failed to cache DEK")
		return
	}

	// --- Populate Request Cache on Set ---
	c.requestCacheMu.Lock()
	// Add a copy to avoid race conditions if entry is modified elsewhere
	// No Expiry field needed here, cleanup routine handles it.
	reqCacheEntry := &types.CacheEntry{
		Value:   entry.Value, // SecureBytes is already a copy/pointer
		Version: entry.Version,
	}
	c.requestCache[key] = reqCacheEntry
	c.requestCacheMu.Unlock()
	// c.logger.Trace().Str("key", key).Msg("Populated request cache on set") // Removed diagnostic log
	// --- End Populate Request Cache ---

	// Revert to original size update logic. Getting accurate size from store interface is hard.
	c.stats.Size++
	c.stats.LastUpdated = time.Now().UTC()

	log.Debug().
		Str("key", key).
		Int("version", version).
		Int("valueSize", len(value)).
		Time("expires", time.Now().Add(c.config.GetEffectiveTTL())).
		Msg("DEK cached successfully in persistent store")
}

// Delete removes a key and its associated value from the cache.
func (c *DEKCache) Delete(key string) {
	if !c.IsEnabled() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.store.Delete(context.Background(), key); err != nil {
		log.Debug().
			Str("key", key).
			Err(err).
			Msg("Failed to delete cache entry")
		return
	}

	if c.stats.Size > 0 {
		c.stats.Size--
	}

	// Only log successful deletion at trace level
	log.Trace().
		Str("key", key).
		Msg("Cache entry deleted")
}

// GetStats returns current cache statistics.
func (c *DEKCache) GetStats(ctx context.Context) types.CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// GetMetrics returns detailed cache performance metrics for monitoring.
func (c *DEKCache) GetMetrics() *CacheMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := float64(c.stats.Hits + c.stats.Misses)
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(c.stats.Hits) / total
	}

	errorRate := float64(0)
	totalOps := atomic.LoadInt64(&c.totalOps)
	if totalOps > 0 {
		errorRate = float64(atomic.LoadInt64(&c.errorCount)) / float64(totalOps)
	}

	// Estimate memory usage
	var memoryUsage int64
	for _, entry := range c.requestCache {
		if entry != nil && entry.Value != nil {
			memoryUsage += int64(len(entry.Value.Get()))
		}
	}

	return &CacheMetrics{
		HitRate:        hitRate,
		MissRate:       1 - hitRate,
		EvictionCount:  atomic.LoadInt64(&c.evictionCount),
		AverageLatency: c.totalLatency / time.Duration(totalOps),
		Size:           c.stats.Size,
		Uptime:         time.Since(c.startTime),
		MemoryUsage:    memoryUsage,
		ErrorRate:      errorRate,
	}
}

// HealthCheck performs a health check on the cache by testing basic operations.
// Returns an error if any operation fails.
func (c *DEKCache) HealthCheck(ctx context.Context) error {
	if !c.IsEnabled() {
		return fmt.Errorf("cache is disabled")
	}

	// Test cache operation
	testKey := fmt.Sprintf("health_check_%s", uuid.New().String())
	testData := []byte("test")
	testVersion := 1

	// Test write
	c.Set(ctx, testKey, testData, testVersion)

	// Test read
	data, version, ok := c.Get(ctx, testKey)
	if !ok {
		return fmt.Errorf("cache read failed")
	}

	if version != testVersion {
		return fmt.Errorf("cache version mismatch")
	}

	// Compare data using SecureBytes Get method
	if data == nil || string(data.Get()) != string(testData) {
		return fmt.Errorf("cache data integrity check failed")
	}

	// Cleanup test data
	c.Delete(testKey)
	return nil
}

// cleanRequestCache removes expired entries from the request-level cache.
// This cache provides an additional layer of optimization for frequent requests.
func (c *DEKCache) cleanRequestCache() int {
	c.requestCacheMu.Lock()
	defer c.requestCacheMu.Unlock()

	entriesCleared := 0

	if time.Since(c.requestCacheTime) >= c.requestCacheTTL {
		entriesCount := len(c.requestCache)
		if entriesCount > 0 {
			// Clear all entries and recreate the map
			for _, entry := range c.requestCache {
				if entry != nil && entry.Value != nil {
					entry.Value.Clear()
				}
			}
			c.requestCache = make(map[string]*types.CacheEntry)
			entriesCleared = entriesCount

			// Only log if entries were actually cleared
			log.Debug().
				Int("cleared_entries", entriesCount).
				Msg("Request cache cleared")
		}
		c.requestCacheTime = time.Now()
	}

	return entriesCleared
}

// startRequestCacheCleanup starts a background routine to periodically clean the request cache.
// Cleanup statistics are logged at regular intervals for monitoring.
func (c *DEKCache) startRequestCacheCleanup() {
	ticker := time.NewTicker(c.requestCacheTTL)
	defer ticker.Stop()

	cleanupCount := 0
	totalEntriesCleared := 0
	lastLogTime := time.Now()
	logInterval := 5 * time.Minute

	for {
		select {
		case <-ticker.C:
			entriesCleared := c.cleanRequestCache()
			cleanupCount++
			totalEntriesCleared += entriesCleared

			// Log cleanup stats periodically instead of every cleanup
			if time.Since(lastLogTime) >= logInterval {
				if cleanupCount > 0 {
					avgEntriesPerCleanup := 0.0
					if cleanupCount > 0 {
						avgEntriesPerCleanup = float64(totalEntriesCleared) / float64(cleanupCount)
					}

					log.Info().
						Int("cleanup_count", cleanupCount).
						Int("total_entries_cleared", totalEntriesCleared).
						Dur("interval", logInterval).
						Time("last_cleanup", c.requestCacheTime).
						Float64("avg_entries_per_cleanup", avgEntriesPerCleanup).
						Msg("Request cache cleanup stats")
				}
				cleanupCount = 0
				totalEntriesCleared = 0
				lastLogTime = time.Now()
			}
		case <-c.done:
			return
		}
	}
}

// Shutdown performs a graceful shutdown of the cache, ensuring all resources are properly cleaned up.
// Returns an error if the cleanup process fails.
func (c *DEKCache) Shutdown(ctx context.Context) error {
	// Signal cleanup routines to stop
	close(c.done)

	// Clean up request cache
	c.cleanRequestCache()

	// Clear main cache
	if err := c.store.Clear(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to clear cache during shutdown")
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	log.Info().
		Int64("total_hits", c.stats.Hits).
		Int64("total_misses", c.stats.Misses).
		Int64("evictions", atomic.LoadInt64(&c.evictionCount)).
		Dur("uptime", time.Since(c.startTime)).
		Msg("Cache shutdown complete")

	return nil
}
