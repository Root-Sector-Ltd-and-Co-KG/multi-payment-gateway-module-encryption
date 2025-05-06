package types

import (
	"context"
	"crypto/subtle"
	"errors"
	"runtime"
	"time"
)

// Common errors
var (
	ErrNotFound = errors.New("key not found in cache")
)

const (
	// DefaultCacheTTL is the default TTL for DEK cache (15 minutes)
	DefaultCacheTTLMinutes = 15
)

// SecureBytes represents a secure byte slice that will be wiped on garbage collection
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a new secure byte slice
func NewSecureBytes(data []byte) *SecureBytes {
	// Create a new byte slice to store the data
	secure := &SecureBytes{
		data: make([]byte, len(data)),
	}
	// Copy data using secure copy to prevent optimizations
	subtle.ConstantTimeCopy(1, secure.data, data)

	// Register finalizer to wipe memory when garbage collected
	runtime.SetFinalizer(secure, (*SecureBytes).Clear)
	return secure
}

// Clear securely wipes the memory
func (s *SecureBytes) Clear() {
	if s.data != nil {
		// Secure wiping - overwrite with zeros
		for i := range s.data {
			s.data[i] = 0
		}
		// Prevent compiler optimizations
		runtime.KeepAlive(s.data)
		s.data = nil
	}
}

// Get returns a copy of the data
func (s *SecureBytes) Get() []byte {
	if s.data == nil {
		return nil
	}
	// Create a copy to prevent external modifications
	result := make([]byte, len(s.data))
	subtle.ConstantTimeCopy(1, result, s.data)
	return result
}

// CacheEntry represents a cached DEK with secure memory handling
type CacheEntry struct {
	Value   *SecureBytes
	Version int
}

// Clear securely wipes the entry
func (e *CacheEntry) Clear() {
	if e.Value != nil {
		e.Value.Clear()
		e.Value = nil
	}
}

// CacheConfig holds configuration for caching
type CacheConfig struct {
	// Enabled indicates whether caching is enabled
	Enabled bool `json:"enabled" bson:"enabled"`

	// TTL is the time-to-live for cached entries in minutes
	// If not set, DefaultCacheTTLMinutes will be used
	TTL int `json:"ttl,omitempty" bson:"ttl,omitempty"`
}

// GetEffectiveTTL returns the effective TTL for the cache
func (c *CacheConfig) GetEffectiveTTL() time.Duration {
	if c.TTL > 0 {
		return time.Duration(c.TTL) * time.Minute
	}
	return time.Duration(DefaultCacheTTLMinutes) * time.Minute
}

// CacheStats holds statistics about the cache
type CacheStats struct {
	Size        int       `json:"size" bson:"size"`
	Hits        int64     `json:"hits" bson:"hits"`
	Misses      int64     `json:"misses" bson:"misses"`
	LastPurged  time.Time `json:"lastPurged" bson:"lastPurged"`
	LastAccess  time.Time `json:"lastAccess" bson:"lastAccess"`
	LastUpdated time.Time `json:"lastUpdated" bson:"lastUpdated"`
}

// Cache defines the interface for caching operations
type Cache interface {
	// Enable enables the cache
	Enable()

	// Disable disables the cache and securely wipes all entries
	Disable()

	// IsEnabled returns whether the cache is enabled
	IsEnabled() bool

	// Clear securely wipes and removes all entries from the cache
	Clear()

	// Get retrieves a value from the cache
	Get(ctx context.Context, key string) (*SecureBytes, int, bool)

	// Set adds a value to the cache with secure memory handling
	Set(ctx context.Context, key string, value []byte, version int)

	// Delete securely wipes and removes a key from the cache
	Delete(key string)

	// GetStats returns cache statistics
	GetStats(ctx context.Context) CacheStats
}
