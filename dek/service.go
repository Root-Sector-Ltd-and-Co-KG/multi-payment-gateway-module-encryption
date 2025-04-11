package dek

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/root-sector/multi-payment-gateway-module-encryption/audit"
	"github.com/root-sector/multi-payment-gateway-module-encryption/cache"
	"github.com/root-sector/multi-payment-gateway-module-encryption/cache/storage"
	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/kms"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
)

// Define custom type for context keys
type contextKey string

const (
	// Event type
	eventType = "dek"

	// Operations
	operationCreate  = "create"
	operationRotate  = "rotate"
	operationUnwrap  = "unwrap"
	operationWrap    = "wrap"
	operationVerify  = "verify"
	operationStatus  = "status"
	operationRestore = "restore"

	// Status values
	statusSuccess = "success"
	statusFailed  = "failed"

	// Context keys
	contextKeyVersion            = "version"
	contextKeyError              = "error"
	contextKeyScope   contextKey = "scope"
	contextKeyOrgID   contextKey = "org_id"

	// Scope values - standardized constants
	scopeSystem = "system"
	scopeOrg    = "organization"

	// Cache key prefixes
	cacheKeyPrefixDEKInfo = "dek_info"
	cacheKeyPrefixDEK     = "dek"

	// Default TTL values
	defaultCacheTTL = 15 * time.Minute
)

// dekService implements the Service interface for DEK management
type dekService struct {
	config        *types.EncryptionConfig
	provider      kms.Provider
	logger        interfaces.AuditLogger
	cache         types.Cache
	store         interfaces.DEKStore
	encryptionKey []byte
	mu            sync.RWMutex
	info          *types.DEKInfo
	status        *types.DEKStatus
	initialized   bool
}

var (
	globalService *dekService
	serviceMu     sync.RWMutex
)

// SetService overrides the global service instance
func SetService(svc interfaces.DEKService) {
	serviceMu.Lock()
	defer serviceMu.Unlock()

	if ds, ok := svc.(*dekService); ok {
		globalService = ds
		log.Debug().Msg("Global DEK service instance updated")
	}
}

// GetService returns the global service instance
func GetService() (interfaces.DEKService, error) {
	serviceMu.RLock()
	if globalService != nil && globalService.initialized {
		serviceMu.RUnlock()
		return globalService, nil
	}
	serviceMu.RUnlock()

	// Create new instance if none exists
	serviceMu.Lock()
	defer serviceMu.Unlock()

	if globalService != nil && globalService.initialized {
		return globalService, nil
	}

	// If we have a partially initialized service, complete its initialization
	if globalService != nil {
		if err := globalService.Initialize(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to initialize existing service: %w", err)
		}
		return globalService, nil
	}

	// Create new service instance with default configuration
	svc := &dekService{
		status: &types.DEKStatus{
			Exists:      false,
			Active:      false,
			Version:     0,
			CreatedAt:   time.Time{},
			UpdatedAt:   time.Time{},
			NeedsRotate: false,
		},
		initialized: false,
	}

	globalService = svc
	return globalService, nil
}

// NewService creates a new DEK service instance
func NewService(config *types.EncryptionConfig, provider kms.Provider, auditLogger interfaces.AuditLogger, store interfaces.DEKStore, cacheStore interfaces.Storage, encryptionKey []byte) (interfaces.DEKService, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	serviceMu.Lock()
	defer serviceMu.Unlock()

	// Check if we already have an initialized service
	if globalService != nil && globalService.initialized {
		return globalService, nil
	}

	// Create service instance
	svc := &dekService{
		config:        config,
		provider:      provider,
		logger:        auditLogger,
		store:         store,
		encryptionKey: encryptionKey,
		status: &types.DEKStatus{
			Exists:      false,
			Active:      false,
			Version:     0,
			CreatedAt:   time.Time{},
			UpdatedAt:   time.Time{},
			Provider:    config.Provider,
			NeedsRotate: false,
		},
	}

	log.Debug().
		Str("providerType", fmt.Sprintf("%T", provider)).
		Bool("providerIsNil", provider == nil).
		Bool("configEnabled", config.Enabled).
		Msg("dek.NewService: Provider received, internal initialization skipped")

	// Update global instance
	globalService = svc

	return svc, nil
}

// createDEKCache creates a new DEK cache with the provided config and storage
func createDEKCache(cacheConfig types.CacheConfig, store interfaces.Storage) types.Cache {
	// Create a new cache config that matches what the NewDEKCache function expects
	config := &types.CacheConfig{
		Enabled: cacheConfig.Enabled,
		TTL:     cacheConfig.TTL,
	}
	return cache.NewDEKCache(config, store)
}

// loadDEKInfo loads DEK info from store with caching
func (s *dekService) loadDEKInfo(ctx context.Context) (*types.DEKInfo, error) {
	// Determine scope and orgID from context
	scope, orgID := s.getScopeFromContext(ctx)
	cacheKey, err := s.getCacheKey(scope, orgID)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate cache key for DEK info")
		// Fallback to fetching directly from store without caching
		return s.store.GetActiveDEK(ctx, scope, orgID)
	}

	// Try to get from cache first if enabled and initialized
	if s.cache != nil && s.cache.IsEnabled() {
		if cached, _, found := s.cache.Get(ctx, cacheKey); found && cached != nil {
			var info types.DEKInfo
			if err := json.Unmarshal(cached.Get(), &info); err == nil {
				log.Debug().Msg("Using cached DEK info")
				return &info, nil
			} else {
				// If unmarshal fails, log and continue to fetch from store
				log.Warn().Err(err).Msg("Failed to unmarshal cached DEK info")
			}
		}
	}

	// Load from store
	info, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("not found")
		}
		return nil, fmt.Errorf("failed to get DEK info from store: %w", err)
	}

	// Handle nil info case
	if info == nil {
		return nil, fmt.Errorf("not found")
	}

	// Cache the result if cache is enabled
	if s.cache != nil && s.cache.IsEnabled() {
		// Marshal DEK info for caching
		dekBytes, marshalErr := json.Marshal(info)
		if marshalErr == nil {
			// Use a background context for caching to avoid deadlocks
			cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.cache.Set(cacheCtx, cacheKey, dekBytes, 1) // Assuming version 1 for now, might need adjustment
			log.Debug().Msg("Cached DEK info")
		} else {
			log.Warn().Err(marshalErr).Msg("Failed to marshal DEK info for caching")
		}
	}

	return info, nil
}

// Initialize initializes the DEK service
func (s *dekService) Initialize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return nil
	}

	log.Info().Msg("Starting DEK service initialization")

	// Initialize cache if enabled and not already initialized
	if s.config != nil && s.config.Cache.Enabled && s.cache == nil {
		s.cache = cache.NewDEKCache(&types.CacheConfig{
			Enabled: true,
			TTL:     s.config.Cache.TTL,
		}, storage.NewMemoryAdapter())
	}

	// Load DEK info without pre-caching first
	info, err := s.loadDEKInfo(ctx)
	if err != nil {
		if err.Error() == "not found" {
			log.Info().Msg("No DEK found during initialization")
			// Don't disable encryption, just return error to indicate DEK needs to be created
			return fmt.Errorf("no DEK found")
		}
		// For other errors, log but continue - might be temporary
		log.Warn().Err(err).Msg("Error loading DEK info during initialization")
	}

	// If we found a DEK, verify it can be unwrapped
	if info != nil && len(info.Versions) > 0 {
		latestVersion := info.Versions[len(info.Versions)-1]
		dek, unwrapErr := s.UnwrapDEK(ctx, &latestVersion)
		if unwrapErr != nil || len(dek) == 0 {
			log.Error().
				Err(unwrapErr).
				Msg("Found DEK but unable to unwrap it")
			// Only return error, let caller decide whether to disable encryption
			return fmt.Errorf("failed to verify DEK unwrapping: %w", unwrapErr)
		}
		log.Info().Msg("Successfully verified DEK unwrapping")
	}

	// Update status
	s.status.Exists = info != nil
	s.status.Active = info != nil && info.Active
	if info != nil {
		s.status.Version = info.Version
		s.status.CreatedAt = info.CreatedAt
		s.status.UpdatedAt = info.UpdatedAt
	} else {
		s.status.Version = 0
		s.status.CreatedAt = time.Time{}
		s.status.UpdatedAt = time.Time{}
	}
	s.info = info

	// Mark as initialized
	s.initialized = true

	// Pre-cache in background only if we have info
	if info != nil && len(info.Versions) > 0 && s.cache != nil && s.cache.IsEnabled() {
		go func() {
			cacheCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			latestVersion := info.Versions[len(info.Versions)-1]
			if dek, err := s.UnwrapDEK(cacheCtx, &latestVersion); err == nil {
				cacheKey, err := s.getUnwrappedCacheKey(cacheCtx, info.Id, latestVersion.Version) // Use Id
				if err == nil {
					s.cache.Set(cacheCtx, cacheKey, dek, latestVersion.Version)
					log.Debug().Msg("Pre-cached DEK successfully")
				} else {
					log.Warn().Err(err).Msg("Failed to generate cache key")
				}
			}
		}()
	}

	log.Info().
		Bool("hasProvider", s.provider != nil).
		Bool("isEnabled", s.config.Enabled).
		Bool("hasInfo", s.info != nil).
		Bool("initialized", s.initialized).
		Str("provider", string(s.config.Provider)).
		Msg("DEK service initialization completed")

	return nil
}

// GetAuditLogger implements Service
func (s *dekService) GetAuditLogger() interface{} {
	return s.logger
}

// GetDEKService implements Service
func (s *dekService) GetDEKService() interface{} {
	return s
}

// GetFieldService implements Service
func (s *dekService) GetFieldService() interface{} {
	return nil
}

// GetTaskProcessor implements Service
func (s *dekService) GetTaskProcessor() interface{} {
	return nil
}

// GetStats implements Service
func (s *dekService) GetStats(ctx context.Context) (interface{}, error) {
	stats, err := s.GetDEKStats(ctx, "system", "")
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// generateDEK generates a new random DEK
func (s *dekService) generateDEK() ([]byte, error) {
	const keySize = 32 // 256-bit key
	key := make([]byte, keySize)

	n, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	if n != keySize {
		return nil, fmt.Errorf("failed to generate complete key: got %d bytes, want %d", n, keySize)
	}

	// Verify key is not all zeros (extremely unlikely but critical check)
	isZero := true
	for _, b := range key {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return nil, fmt.Errorf("generated key is all zeros")
	}

	return key, nil
}

// getScopeFromContext extracts scope and orgID from context with improved validation
func (s *dekService) getScopeFromContext(ctx context.Context) (scope string, orgID string) {
	// Try to get scope from context using the audit package key type
	if scopeVal := ctx.Value(audit.KeyScope); scopeVal != nil {
		if scopeStr, ok := scopeVal.(string); ok {
			scope = scopeStr
		}
	}

	// Try to get orgID from context using the audit package key type
	if orgIDVal := ctx.Value(audit.KeyOrgID); orgIDVal != nil {
		if orgIDStr, ok := orgIDVal.(string); ok {
			orgID = orgIDStr
		}
	}

	// Validate and normalize scope
	switch scope {
	case scopeSystem:
		if orgID != "" {
			log.Warn().
				Str("scope", scope).
				Str("orgID", orgID).
				Msg("System scope should not have an orgID, ignoring orgID")
			orgID = ""
		}
	case scopeOrg:
		if orgID == "" {
			log.Warn().
				Str("scope", scope).
				Msg("Organization scope set but no orgID provided")
		}
	default:
		if scope != "" {
			log.Warn().
				Str("invalidScope", scope).
				Msg("Invalid scope provided, defaulting to system scope")
		}
		scope = scopeSystem
		orgID = ""
	}

	log.Debug().
		Str("scope", scope).
		Str("orgID", orgID).
		Msg("Extracted scope and orgID from context")

	return scope, orgID
}

// getWrapContext builds the wrap context based on scope and orgID
func (s *dekService) getWrapContext(scope, orgID string) []byte {
	if scope == scopeSystem {
		return []byte(scopeSystem)
	} else if scope == scopeOrg || scope == "organization" {
		if orgID != "" {
			// Always use the constant scopeOrg for consistency
			return []byte(fmt.Sprintf("%s:%s", scopeOrg, orgID))
		}
	}
	return []byte(scopeSystem)
}

// wrapDEK wraps a DEK using the configured KMS provider
func (s *dekService) wrapDEK(ctx context.Context, key []byte, scope string, orgID string) (*types.DEKVersion, error) {
	if key == nil {
		return nil, fmt.Errorf("key is required")
	}

	// Get wrapper from provider
	wrapper := s.provider.GetWrapper()
	if wrapper == nil {
		return nil, fmt.Errorf("KMS wrapper not available")
	}

	// Create wrap context with timeout
	wrapCtx, wrapCancel := context.WithTimeout(ctx, 5*time.Second)
	defer wrapCancel()

	// If scope is empty, get from context
	if scope == "" {
		scope, _ = s.getScopeFromContext(ctx)
	}

	// Build wrap context using orgID if provided
	wrapContext := s.getWrapContext(scope, orgID)

	log.Debug().
		Str("scope", scope).
		Hex("wrapContext", wrapContext).
		Msg("Using wrap context for encryption")

	// Set up wrap options
	var opts []wrapping.Option
	if len(wrapContext) > 0 {
		opts = append(opts, wrapping.WithAad(wrapContext))
	}

	// Encrypt key using KMS
	blobInfo, err := wrapper.Encrypt(wrapCtx, key, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	if blobInfo == nil {
		return nil, fmt.Errorf("wrapped key info is nil")
	}

	log.Debug().
		Bool("hasIv", len(blobInfo.Iv) > 0).
		Bool("hasCiphertext", len(blobInfo.Ciphertext) > 0).
		Msg("Received blob info from KMS")

	// Create version with wrapped data
	version := &types.DEKVersion{
		Version:     1,
		BlobInfo:    blobInfo,
		CreatedAt:   time.Now().UTC(),
		WrapContext: wrapContext, // Ensure WrapContext is stored
	}

	// Verify unwrap
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var verifyOpts []wrapping.Option
	if len(wrapContext) > 0 {
		verifyOpts = append(verifyOpts, wrapping.WithAad(wrapContext))
	}

	unwrapped, err := wrapper.Decrypt(verifyCtx, version.BlobInfo, verifyOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to verify wrapped key: %w", err)
	}

	if !bytes.Equal(unwrapped, key) {
		return nil, fmt.Errorf("unwrapped key does not match original")
	}

	log.Debug().
		Msg("Successfully created and verified DEK version")

	version.WrapContext = wrapContext
	return version, nil
}

// CreateDEK creates a new DEK and wraps it with KMS
func (s *dekService) CreateDEK(ctx context.Context, scope string, orgID string) (*types.DEKInfo, error) {
	s.mu.RLock() // Use RLock first to check internal state
	// Quick check if we *know* a DEK exists internally
	if s.info != nil && s.info.Active {
		s.mu.RUnlock()
		return nil, fmt.Errorf("DEK already active in service state for scope %s/%s", scope, orgID)
	}
	s.mu.RUnlock()

	// Now check the persistent store definitively WITHOUT holding the main service lock
	log.Debug().Str("scope", scope).Str("orgID", orgID).Msg("Checking store for existing active DEK before creation")
	existingInfo, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil && err != mongo.ErrNoDocuments { // Check specifically for ErrNoDocuments
		log.Error().Err(err).Str("scope", scope).Str("orgID", orgID).Msg("Error checking store for existing DEK")
		// Don't return internal store errors directly, wrap them
		return nil, fmt.Errorf("failed to verify existing DEK status: %w", err)
	} else if existingInfo != nil {
		log.Warn().Str("scope", scope).Str("orgID", orgID).Str("existingDEKId", existingInfo.Id).Msg("DEK already exists in store")
		return nil, fmt.Errorf("DEK already exists in store for scope %s/%s", scope, orgID)
	}
	log.Debug().Str("scope", scope).Str("orgID", orgID).Msg("No existing active DEK found in store, proceeding with creation")

	// --- Acquire lock BEFORE generating/wrapping DEK ---
	s.mu.Lock()

	// Generate new DEK (no lock needed)
	newDEK, err := s.generateDEK()
	if err != nil {
		s.mu.Unlock() // Release lock on error
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Wrap (encrypt) the DEK using KMS
	wrappedVersion, err := s.wrapDEK(ctx, newDEK, scope, orgID)

	if err != nil {
		s.mu.Unlock() // Release lock on error
		// Log failure if wrapDEK failed
		s.logAuditEvent(ctx, "dek", "create", "failure", 0, fmt.Errorf("failed to wrap DEK: %w", err))
		return nil, fmt.Errorf("failed to wrap DEK: %w", err)
	}

	// --- Release lock AFTER wrapping ---
	s.mu.Unlock()

	// Create DEK info with wrapped version (no lock needed here)
	dekInfo := &types.DEKInfo{
		Id:        uuid.New().String(),
		Version:   1,
		Active:    true,
		Versions:  []types.DEKVersion{*wrappedVersion},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Store DEK info (no lock needed for store operation itself)
	if err := s.store.StoreDEK(ctx, dekInfo, scope, orgID); err != nil {
		// Log failure before returning
		s.logAuditEvent(ctx, "dek", "create", "failure", 0, fmt.Errorf("failed to store DEK: %w", err))
		return nil, fmt.Errorf("failed to store DEK: %w", err)
	}

	// --- Critical section: Update internal state ---
	s.mu.Lock() // Acquire write lock *only* for updating internal state
	s.info = dekInfo
	s.status = &types.DEKStatus{
		Exists:      true,
		Active:      true,
		Version:     dekInfo.Version,
		CreatedAt:   dekInfo.CreatedAt,
		UpdatedAt:   dekInfo.UpdatedAt,
		Provider:    s.config.Provider,
		NeedsRotate: false,
	}
	s.mu.Unlock() // Release lock after updating internal state
	// --- End Critical section ---

	// Log success
	s.logAuditEvent(ctx, "dek", "create", "success", dekInfo.Version, nil)

	return dekInfo, nil
}

// DeleteDEK deletes the current DEK
func (s *dekService) DeleteDEK(ctx context.Context, scope string, orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear from cache if enabled
	if s.cache != nil {
		cacheKey, err := s.getCacheKey(scope, orgID)
		if err == nil {
			s.cache.Delete(cacheKey)
		} else {
			log.Warn().Err(err).Msg("Failed to generate cache key for deletion")
		}
	}

	// Delete from store
	if err := s.store.DeleteDEK(ctx, orgID, scope); err != nil {
		s.logAuditEvent(ctx, eventType, operationRestore, statusFailed, 0, err)
		return fmt.Errorf("failed to delete DEK: %w", err)
	}

	// Log success
	s.logAuditEvent(ctx, eventType, operationRestore, statusSuccess, 0, nil)
	return nil
}

// GetDEK retrieves a DEK by ID
func (s *dekService) GetDEK(ctx context.Context, id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() {
		if dek, _, found := s.cache.Get(ctx, id); found {
			return dek.Get(), nil
		}
	}

	// Get DEK info from store - use system scope as default
	info, err := s.store.GetDEK(ctx, id, "system")
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}

	// Get latest version
	latestVersion := info.Versions[len(info.Versions)-1]

	// Unwrap the key
	dek, err := s.UnwrapDEK(ctx, &latestVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	// Cache the unwrapped key
	if s.cache != nil && s.cache.IsEnabled() {
		s.cache.Set(ctx, id, dek, latestVersion.Version)
	}

	return dek, nil
}

func (s *dekService) GetDEKVersion(ctx context.Context, id string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() {
		if _, version, found := s.cache.Get(ctx, id); found {
			return version, nil
		}
	}

	return 1, nil // Default version for new DEKs
}

func (s *dekService) GetDEKInfo(ctx context.Context, id string) (*types.DEKInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version, err := s.GetDEKVersion(ctx, id)
	if err != nil {
		return nil, err
	}

	return &types.DEKInfo{
		Id:        id, // Use Id
		Version:   version,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (s *dekService) GetDEKStats(ctx context.Context, scope string, id string) (*types.DEKStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := types.DEKStats{
		LastOperation: time.Now(),
	}

	if s.cache != nil {
		cacheStats := s.cache.GetStats(ctx)
		stats.TotalDEKs = cacheStats.Size
		stats.ActiveDEKs = cacheStats.Size
	}

	return &stats, nil
}

// logAuditEvent logs an audit event with the given parameters
func (s *dekService) logAuditEvent(ctx context.Context, eventType, operation, status string, version int, err error) {
	// Create context map with string keys
	contextMap := map[string]string{ // Renamed variable to avoid conflict
		string(contextKeyVersion): fmt.Sprintf("%d", version),
		string(contextKeyScope):   scopeSystem,
	}

	// Add error to context if present
	if err != nil {
		contextMap[string(contextKeyError)] = err.Error() // Use contextMap
	}

	// Create audit event
	event := &types.AuditEvent{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		EventType:  eventType,
		Operation:  operation,
		Status:     status,
		DEKVersion: version,
		Context:    contextMap, // Use contextMap
	}

	// Log event, print to stdout if logger fails
	if s.logger != nil { // Check if logger is initialized
		if logErr := s.logger.LogEvent(ctx, event); logErr != nil {
			fmt.Printf("Failed to log audit event: %v\n", logErr)
		}
	} else {
		fmt.Printf("Audit logger not initialized. Event: %+v\n", event)
	}
}

// getCacheKey returns a properly formatted cache key based on scope and orgID
func (s *dekService) getCacheKey(scope, orgID string) (string, error) {
	if scope == scopeSystem {
		return fmt.Sprintf("%s:%s", cacheKeyPrefixDEKInfo, scopeSystem), nil
	}

	// If scope is org and orgID is not empty, use org:orgID format
	if scope == scopeOrg && orgID != "" {
		return fmt.Sprintf("%s:%s:%s", cacheKeyPrefixDEKInfo, scopeOrg, orgID), nil
	}

	// Return error for invalid scope
	return "", fmt.Errorf("invalid scope or missing organization ID: scope=%s, orgID=%s", scope, orgID)
}

// getUnwrappedCacheKey generates a cache key for unwrapped DEKs
func (s *dekService) getUnwrappedCacheKey(ctx context.Context, dekId string, version int) (string, error) { // Use dekId
	scope, orgID := s.getScopeFromContext(ctx)

	if scope == scopeSystem {
		return fmt.Sprintf("%s:%s:%s:v%d", cacheKeyPrefixDEK, scopeSystem, dekId, version), nil // Use dekId
	}

	// Only use org scope if both scope is org and orgID is provided
	if scope == scopeOrg && orgID != "" {
		return fmt.Sprintf("%s:%s:%s:%s:v%d", cacheKeyPrefixDEK, scopeOrg, orgID, dekId, version), nil // Use dekId
	}

	// Return error for invalid scope
	return "", fmt.Errorf("invalid scope or missing organization ID: scope=%s, orgID=%s", scope, orgID)
}

// getCacheTTL returns the effective cache TTL
func (s *dekService) getCacheTTL() time.Duration {
	if s.config != nil && s.config.Cache.TTL > 0 {
		return time.Duration(s.config.Cache.TTL) * time.Second
	}
	return defaultCacheTTL
}

// UnwrapDEK unwraps a DEK version using the configured KMS provider
func (s *dekService) UnwrapDEK(ctx context.Context, version *types.DEKVersion) ([]byte, error) {
	if version == nil {
		return nil, fmt.Errorf("version is required")
	}

	log.Debug().
		Int("version", int(version.Version)).
		Str("keyId", version.BlobInfo.KeyInfo.KeyId). // Use KeyId
		Bool("hasWrappedKey", version.BlobInfo.KeyInfo != nil && len(version.BlobInfo.KeyInfo.WrappedKey) > 0).
		Bool("hasCiphertext", len(version.BlobInfo.Ciphertext) > 0).
		Bool("hasIv", len(version.BlobInfo.Iv) > 0).
		Bool("hasHmac", len(version.BlobInfo.Hmac) > 0).
		Msg("Starting DEK unwrap")

	// Use the stored BlobInfo directly
	if version.BlobInfo == nil {
		return nil, fmt.Errorf("no blob info available")
	}

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() && s.info != nil {
		cacheKey, err := s.getUnwrappedCacheKey(ctx, s.info.Id, version.Version) // Use Id
		if err == nil {
			if dek, _, found := s.cache.Get(ctx, cacheKey); found && dek != nil && len(dek.Get()) > 0 {
				log.Debug().
					Str("cacheKey", cacheKey).
					Int("version", version.Version).
					Int("dekLength", len(dek.Get())).
					Msg("Using cached unwrapped DEK")
				return dek.Get(), nil
			}
			log.Debug().
				Str("cacheKey", cacheKey).
				Int("version", version.Version).
				Msg("Cache miss for unwrapped DEK")
		} else {
			log.Warn().Err(err).Msg("Failed to generate unwrapped cache key")
		}
	}

	// Get wrapper from provider
	wrapper := s.provider.GetWrapper()
	if wrapper == nil {
		log.Error().Msg("KMS wrapper not available")
		return nil, fmt.Errorf("KMS wrapper not available")
	}

	// Set up wrap context
	var opts []wrapping.Option
	var finalAAD []byte

	// AAD MUST come from the stored WrapContext in the version.
	// If it's missing, decryption cannot proceed safely.
	if len(version.WrapContext) == 0 {
		err := fmt.Errorf("missing wrap context in DEK version %d, cannot determine AAD for decryption", version.Version)
		log.Error().Err(err).Msg("UnwrapDEK failed")
		return nil, err
	}

	finalAAD = version.WrapContext
	log.Debug().
		Hex("version.WrapContext", version.WrapContext).
		Hex("finalAAD", finalAAD).
		Msg("AAD Source: Using wrap context stored in version")
	opts = append(opts, wrapping.WithAad(finalAAD))

	// Decrypt using KMS with the stored blob info
	logEntry := log.Debug()
	if version.BlobInfo.KeyInfo != nil {
		logEntry = logEntry.Str("keyId", version.BlobInfo.KeyInfo.KeyId) // Use KeyId only if KeyInfo exists
	} else {
		logEntry = logEntry.Str("keyId", "<nil KeyInfo>")
	}
	logEntry.
		Hex("finalAADPassedToKMS", finalAAD). // Log the AAD being passed explicitly
		Bool("hasWrappedKey", len(version.BlobInfo.KeyInfo.WrappedKey) > 0).
		Bool("hasCiphertext", len(version.BlobInfo.Ciphertext) > 0).
		Bool("hasIv", len(version.BlobInfo.Iv) > 0).
		Bool("hasHmac", len(version.BlobInfo.Hmac) > 0).
		Uint64("mechanism", version.BlobInfo.KeyInfo.Mechanism).
		Hex("iv", version.BlobInfo.Iv).
		Hex("ciphertext", version.BlobInfo.Ciphertext).
		Msg("Attempting to unwrap DEK with KMS")

	dek, err := wrapper.Decrypt(ctx, version.BlobInfo, opts...)
	if err != nil {
		logEntry := log.Error().Err(err)
		if version.BlobInfo.KeyInfo != nil {
			logEntry = logEntry.Str("keyId", version.BlobInfo.KeyInfo.KeyId) // Use KeyId only if KeyInfo exists
		} else {
			logEntry = logEntry.Str("keyId", "<nil KeyInfo>")
		}
		logEntry.
			Hex("aadUsed", finalAAD). // Log AAD again on error
			Hex("iv", version.BlobInfo.Iv).
			Hex("ciphertext", version.BlobInfo.Ciphertext).
			Msg("Failed to unwrap DEK with KMS")
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	if len(dek) == 0 {
		log.Error().Msg("Unwrapped DEK is empty")
		return nil, fmt.Errorf("unwrapped key is empty")
	}

	log.Debug().
		Int("dekLength", len(dek)).
		Msg("Successfully unwrapped DEK")

	// Cache the unwrapped DEK if enabled
	if s.cache != nil && s.cache.IsEnabled() && s.info != nil {
		cacheKey, err := s.getUnwrappedCacheKey(ctx, s.info.Id, version.Version) // Use Id
		if err == nil {
			ttl := s.getCacheTTL()
			s.cache.Set(ctx, cacheKey, dek, version.Version)
			log.Debug().
				Str("cacheKey", cacheKey).
				Int("version", version.Version).
				Int("dekLength", len(dek)).
				Dur("ttl", ttl).
				Time("expires", time.Now().Add(ttl)).
				Msg("DEK cached successfully")
		} else {
			log.Warn().Err(err).Msg("Failed to generate cache key for caching DEK")
		}
	}

	return dek, nil
}

// RotateDEK rotates the current DEK
func (s *dekService) RotateDEK(ctx context.Context, scope string, orgID string, force bool) (*types.DEKInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get current DEK info
	currentInfo, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current DEK: %w", err)
	}

	if currentInfo == nil {
		return nil, fmt.Errorf("no active DEK found")
	}

	// Log current info for debugging
	log.Debug().
		Str("dekID", currentInfo.Id). // Use Id
		Int("currentVersion", currentInfo.Version).
		Int("numVersions", len(currentInfo.Versions)).
		Bool("forceFullReencryption", force).
		Msg("Current DEK info before rotation")

	if len(currentInfo.Versions) == 0 {
		return nil, fmt.Errorf("current DEK has no versions")
	}

	// Get current version of DEK
	currentVersion := currentInfo.Version

	var newVersion *types.DEKVersion
	var plaintextDEK []byte
	var isSameKey bool

	// Check if this is a full re-encryption (force=true) or envelope encryption (force=false)
	if force {
		// FULL RE-ENCRYPTION: Generate a completely new DEK key
		log.Info().Msg("Performing FULL RE-ENCRYPTION with new DEK key")

		// Generate new DEK key
		plaintextDEK, err = s.generateDEK()
		if err != nil {
			return nil, fmt.Errorf("failed to generate new DEK key for full re-encryption: %w", err)
		}

		// Wrap the new DEK
		newVersion, err = s.wrapDEK(ctx, plaintextDEK, scope, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap new DEK for full re-encryption: %w", err)
		}

		isSameKey = false // Key has changed
	} else {
		// ENVELOPE ENCRYPTION: Just re-wrap the same plaintext DEK
		log.Info().Msg("Performing ENVELOPE ENCRYPTION (re-wrapping same DEK key)")

		// First, find the current version in the versions array
		var currentVersionData *types.DEKVersion
		for i, v := range currentInfo.Versions {
			if v.Version == currentVersion {
				currentVersionData = &currentInfo.Versions[i]
				break
			}
		}

		if currentVersionData == nil {
			return nil, fmt.Errorf("could not find current DEK version in versions array")
		}

		// Get plaintext DEK by unwrapping the current version
		plaintextDEK, err = s.UnwrapDEK(ctx, currentVersionData)
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap current DEK version: %w", err)
		}

		// Add detailed logging for the original DEK
		log.Debug().
			Int("currentVersion", currentVersion).
			Int("dekLength", len(plaintextDEK)).
			Hex("dekKeyHash", createKeyHash(plaintextDEK)). // Log a hash of the key for comparison
			Msg("Successfully unwrapped current DEK version")

		// DO NOT generate a new plaintext DEK, re-use the existing one
		// This is the key difference between envelope encryption and full re-encryption

		// Just re-wrap the EXACT SAME plaintext DEK with a new KMS key wrapping
		newVersion, err = s.wrapDEK(ctx, plaintextDEK, scope, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap DEK for new version: %w", err)
		}

		// Add detailed logging for the new wrapped DEK
		log.Debug().
			Int("newVersion", currentVersion+1).
			Hex("dekKeyHash", createKeyHash(plaintextDEK)). // Should be the same hash
			Msg("Successfully re-wrapped same DEK key for new version")

		isSameKey = true // Same key, just re-wrapped
	}

	// Increment version number
	newVersion.Version = currentVersion + 1

	// Create updated DEK info (maintaining same ID)
	updatedInfo := &types.DEKInfo{
		Id:        currentInfo.Id,                            // Use Id, Keep same ID
		Version:   currentVersion + 1,                        // Increment version
		Active:    true,                                      // New version is active
		Versions:  append(currentInfo.Versions, *newVersion), // Add new version to existing versions
		CreatedAt: currentInfo.CreatedAt,                     // Keep creation time
		UpdatedAt: time.Now(),                                // Update time
	}

	// Log update for debugging
	log.Debug().
		Str("dekID", updatedInfo.Id). // Use Id
		Int("oldVersion", currentVersion).
		Int("newVersion", updatedInfo.Version).
		Int("numVersions", len(updatedInfo.Versions)).
		Bool("isSameKey", isSameKey).
		Bool("isFullReencryption", force).
		Msg("Updated DEK info for rotation")

	// Store the updated DEK
	if err := s.store.StoreDEK(ctx, updatedInfo, scope, orgID); err != nil {
		return nil, fmt.Errorf("failed to store updated DEK: %w", err)
	}

	// Update service state
	s.info = updatedInfo
	s.status = &types.DEKStatus{
		Exists:      true,
		Active:      true,
		Version:     updatedInfo.Version,
		CreatedAt:   updatedInfo.CreatedAt,
		UpdatedAt:   updatedInfo.UpdatedAt,
		Provider:    s.config.Provider,
		NeedsRotate: false,
	}

	// Clear cache
	if s.cache != nil {
		cacheKey, err := s.getCacheKey(scope, orgID)
		if err == nil {
			s.cache.Delete(cacheKey)
			log.Debug().
				Str("cacheKey", cacheKey).
				Msg("Cleared DEK cache after rotation")
		} else {
			log.Warn().Err(err).Msg("Failed to generate cache key for clearing cache after rotation")
		}
	}

	return updatedInfo, nil
}

// createKeyHash creates a hash of a key for logging purposes
// This only logs a hash of the key, not the key itself
func createKeyHash(key []byte) []byte {
	if len(key) == 0 {
		return []byte{}
	}

	// Create a simple hash for comparison in logs
	// This is not for security, just for debugging
	hash := make([]byte, 8)
	for i := 0; i < len(key) && i < 32; i++ {
		hash[i%8] ^= key[i]
	}
	return hash
}

// GetActiveDEK returns the current active DEK for field encryption
func (s *dekService) GetActiveDEK(ctx context.Context, scope string, orgID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() && s.info != nil {
		cacheKey, err := s.getUnwrappedCacheKey(ctx, s.info.Id, s.info.Version) // Use Id
		if err == nil {
			if dek, version, found := s.cache.Get(ctx, cacheKey); found && dek != nil && len(dek.Get()) > 0 {
				// Verify the cached version matches the current version
				if version == s.info.Version {
					log.Debug().
						Str("scope", scope).
						Str("orgID", orgID).
						Int("version", version).
						Str("cacheKey", cacheKey).
						Int("dekLength", len(dek.Get())).
						Msg("Using cached active DEK")
					return dek.Get(), nil
				}
				log.Debug().
					Str("scope", scope).
					Str("orgID", orgID).
					Int("cachedVersion", version).
					Int("currentVersion", s.info.Version).
					Msg("Cached DEK version mismatch, will fetch fresh")
			}
		} else {
			log.Warn().Err(err).Msg("Failed to generate unwrapped cache key")
		}
	}

	// Get DEK info from store
	log.Debug().
		Str("scope", scope).
		Str("id", orgID).
		Bool("hasStore", s.store != nil).
		Msg("Getting DEK info")

	info, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active DEK: %w", err)
	}

	if info == nil || !info.Active || len(info.Versions) == 0 {
		return nil, fmt.Errorf("no active DEK found")
	}

	// Get latest version
	latestVersion := info.Versions[len(info.Versions)-1]

	// Update service state
	s.info = info

	// Unwrap and cache the DEK
	return s.UnwrapDEK(ctx, &latestVersion)
}

// Delete removes the current DEK
func (s *dekService) Delete(ctx context.Context) error {
	if s.info == nil {
		err := fmt.Errorf("DEK not initialized")
		s.logAuditEvent(ctx, eventType, operationRestore, statusFailed, 0, err)
		return err
	}

	version := s.info.Version

	// Log success before deletion
	s.logAuditEvent(ctx, eventType, operationRestore, statusSuccess, version, nil)

	// Clear DEK info and status
	s.info = nil
	s.status = &types.DEKStatus{
		Exists:      false,
		Active:      false,
		Version:     0,
		CreatedAt:   time.Time{},
		UpdatedAt:   time.Time{},
		Provider:    s.config.Provider,
		NeedsRotate: false,
	}

	return nil
}

// GetDEKStatus gets the status of a DEK for a specific scope and organization
func (s *dekService) GetDEKStatus(ctx context.Context, scope string, orgID string) (*types.DEKStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get DEK info
	cacheKey, err := s.getCacheKey(scope, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cache key: %w", err)
	}
	info, err := s.GetDEKInfo(ctx, cacheKey) // Pass cacheKey as ID? Seems wrong. Should pass orgID or "" for system.
	if err != nil {
		// If not found, return default status
		if strings.Contains(err.Error(), "not found") {
			return &types.DEKStatus{Exists: false, Active: false, Provider: s.config.Provider}, nil
		}
		return nil, err
	}

	// Create status
	status := &types.DEKStatus{
		Exists:      true,
		Active:      info.Active,
		Version:     info.Version,
		CreatedAt:   info.CreatedAt,
		UpdatedAt:   info.UpdatedAt,
		Provider:    s.config.Provider,
		NeedsRotate: false, // TODO: Implement rotation check logic
	}

	return status, nil
}

// GetInfo implements Service
func (s *dekService) GetInfo(ctx context.Context, scope string, id string) (*types.DEKInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	log.Debug().
		Str("scope", scope).
		Str("id", id).
		Bool("hasStore", s.store != nil).
		Msg("Getting DEK info")

	// Get DEK info from store
	info, err := s.store.GetActiveDEK(ctx, scope, id) // Use GetActiveDEK for consistency? Or GetDEK?
	if err != nil {
		log.Error().
			Err(err).
			Str("scope", scope).
			Str("id", id).
			Msg("Failed to get DEK info from store")
		return nil, fmt.Errorf("failed to get DEK info: %w", err)
	}

	// If no DEK exists, return nil
	if info == nil {
		log.Debug().
			Str("scope", scope).
			Str("id", id).
			Msg("No DEK info found")
		return nil, nil
	}

	log.Debug().
		Str("scope", scope).
		Str("id", id).
		Str("dekId", info.Id). // Use Id
		Int("version", info.Version).
		Int("numVersions", len(info.Versions)).
		Bool("active", info.Active).
		Time("createdAt", info.CreatedAt).
		Time("updatedAt", info.UpdatedAt).
		Msg("Found DEK info")

	return info, nil
}

// GetStatus implements Service
func (s *dekService) GetStatus(ctx context.Context, scope string, orgID string) (*types.DEKStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If service is not properly initialized, return disabled status
	if s.config == nil || s.store == nil {
		return &types.DEKStatus{
			Exists:      false,
			Active:      false,
			Version:     0,
			CreatedAt:   time.Time{},
			UpdatedAt:   time.Time{},
			Provider:    "",
			NeedsRotate: false,
		}, nil
	}

	// Get active DEK from store
	info, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK status: %w", err)
	}

	// If no DEK exists, return status indicating that
	if info == nil {
		return &types.DEKStatus{
			Exists:      false,
			Active:      false,
			Version:     0,
			CreatedAt:   time.Time{},
			UpdatedAt:   time.Time{},
			Provider:    s.config.Provider,
			NeedsRotate: false,
		}, nil
	}

	// Return status for existing DEK
	return &types.DEKStatus{
		Exists:      true,
		Active:      info.Active,
		Version:     info.Version,
		CreatedAt:   info.CreatedAt,
		UpdatedAt:   info.UpdatedAt,
		Provider:    s.config.Provider,
		NeedsRotate: false, // TODO: Implement rotation check logic
	}, nil
}

// Create implements Service
func (s *dekService) Create(ctx context.Context, scope string, id string) error {
	_, err := s.CreateDEK(ctx, scope, id)
	return err
}

// Rotate implements Service
func (s *dekService) Rotate(ctx context.Context, scope string, id string) error {
	_, err := s.RotateDEK(ctx, scope, id, false)
	return err
}

// Restore implements Service
func (s *dekService) Restore(ctx context.Context, scope string, id string) error {
	return s.DeleteDEK(ctx, scope, id)
}
