package field

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/root-sector/multi-payment-gateway-module-encryption/cache/storage"
	"github.com/root-sector/multi-payment-gateway-module-encryption/dek"

	"github.com/root-sector/multi-payment-gateway-module-encryption/dek/store"
	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/kms"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
)

// Factory creates field encryption services
type Factory struct {
	encryptionConfig *types.EncryptionConfig
	auditLogger      interfaces.AuditLogger
	db               *mongo.Database
	kmsProvider      kms.Provider
	encryptionKey    []byte
	dekServices      sync.Map // Cache for DEK services
	mu               sync.RWMutex
}

// NewFactory creates a new field service factory
func NewFactory(config *types.EncryptionConfig, logger interfaces.AuditLogger, db *mongo.Database, kmsProvider kms.Provider, encryptionKey []byte) *Factory {
	return &Factory{
		encryptionConfig: config,
		auditLogger:      logger,
		db:               db,
		kmsProvider:      kmsProvider,
		encryptionKey:    encryptionKey,
	}
}

// CreateFieldService creates a new field service instance
// If encryption is disabled, it returns a no-op service that only handles plaintext
// If encryption is enabled, it returns a fully functional encryption service
func (f *Factory) CreateFieldService(ctx context.Context, scope string, id string) (interfaces.FieldService, error) {
	log.Debug().
		Str("scope", scope).
		Str("id", id).
		Bool("encryptionEnabled", f.encryptionConfig != nil && f.encryptionConfig.Enabled).
		Msg("Creating field service")

	// If encryption is not enabled, create a basic no-op service
	if f.encryptionConfig == nil || !f.encryptionConfig.Enabled {
		log.Debug().
			Str("scope", scope).
			Str("id", id).
			Msg("Encryption is disabled, creating no-op service")
		return NewFieldService(nil, f.auditLogger, scope, id), nil
	}

	// Generate a unique cache key for this scope/id combination
	cacheKey := fmt.Sprintf("%s:%s", scope, id)

	// Check if we have a cached DEK service for this scope/id
	f.mu.RLock()
	if cachedSvc, ok := f.dekServices.Load(cacheKey); ok {
		f.mu.RUnlock()
		if dekSvc, ok := cachedSvc.(interfaces.DEKService); ok {
			log.Debug().
				Str("scope", scope).
				Str("id", id).
				Msg("Using cached DEK service")
			return NewFieldService(dekSvc, f.auditLogger, scope, id), nil
		}
		// Invalid cache entry, remove it
		f.mu.Lock()
		f.dekServices.Delete(cacheKey)
		f.mu.Unlock()
		log.Warn().
			Str("scope", scope).
			Str("id", id).
			Msg("Invalid cached DEK service, creating new one")
	} else {
		f.mu.RUnlock()
	}

	// Create MongoDB store
	log.Debug().Msg("Creating MongoDB store")
	mongoStore := store.NewMongoDBStore(f.db)

	// Create cache storage
	var cacheStore interfaces.Storage
	if f.encryptionConfig.Cache.Enabled {
		log.Debug().Msg("Creating cache storage")
		cacheStore = storage.NewMemoryAdapter()
	}

	// Create DEK service with proper configuration
	log.Debug().Msg("Creating DEK service")
	dekService, err := dek.NewService(f.encryptionConfig, f.kmsProvider, f.auditLogger, mongoStore, cacheStore, f.encryptionKey)
	if err != nil {
		log.Error().Err(err).
			Str("scope", scope).
			Str("id", id).
			Msg("Failed to create DEK service")
		return nil, fmt.Errorf("failed to create DEK service: %w", err)
	}

	// Initialize the DEK service
	log.Debug().Msg("Initializing DEK service")
	if err := dekService.Initialize(ctx); err != nil {
		log.Error().Err(err).
			Str("scope", scope).
			Str("id", id).
			Msg("Failed to initialize DEK service")
		return nil, fmt.Errorf("failed to initialize DEK service: %w", err)
	}

	// Cache the DEK service
	f.dekServices.Store(cacheKey, dekService)

	// Create field service with DEK service
	log.Debug().Msg("Creating field service with DEK")
	return NewFieldService(dekService, f.auditLogger, scope, id), nil
}

// CreateSystemFieldService creates a field service for system-wide encryption
func (f *Factory) CreateSystemFieldService(ctx context.Context) (interfaces.FieldService, error) {
	return f.CreateFieldService(ctx, "system", "")
}

// CreateOrganizationFieldService creates a field service for organization-specific encryption
func (f *Factory) CreateOrganizationFieldService(ctx context.Context, orgId string) (interfaces.FieldService, error) {
	return f.CreateFieldService(ctx, "organization", orgId)
}
