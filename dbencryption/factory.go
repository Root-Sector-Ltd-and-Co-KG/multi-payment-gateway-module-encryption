package dbencryption

import (
	"context"
	"fmt"
	"time"

	"github.com/root-sector/multi-payment-gateway-module-encryption/audit"
	"github.com/root-sector/multi-payment-gateway-module-encryption/cache/storage"
	"github.com/root-sector/multi-payment-gateway-module-encryption/dek"
	dekstore "github.com/root-sector/multi-payment-gateway-module-encryption/dek/store"
	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/kms"
	encTypes "github.com/root-sector/multi-payment-gateway-module-encryption/types"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ZerologAdapter adapts zerolog to dbencryption.Logger interface
type ZerologAdapter struct {
	logger zerolog.Logger
}

func NewZerologAdapter(component string) *ZerologAdapter {
	logger := log.With().Str("component", component).Logger()
	return &ZerologAdapter{
		logger: logger,
	}
}

func (z *ZerologAdapter) Printf(format string, v ...interface{}) {
	z.logger.Debug().Msgf(format, v...)
}

// LogEvent implements interfaces.AuditLogger interface
func (z *ZerologAdapter) LogEvent(ctx context.Context, event *encTypes.AuditEvent) error {
	// Log audit event using zerolog
	z.logger.Info().
		Str("event_type", event.EventType).
		Str("operation", event.Operation).
		Str("status", event.Status).
		Int("dek_version", event.DEKVersion).
		Interface("context", event.Context).
		Interface("metadata", event.Metadata).
		Msg("Audit event")
	return nil
}

// GetEvents implements interfaces.AuditLogger interface
func (z *ZerologAdapter) GetEvents(ctx context.Context, filters map[string]interface{}) ([]*encTypes.AuditEvent, error) {
	// This method is mainly for compatibility - zerolog doesn't store events
	return nil, fmt.Errorf("GetEvents not supported by ZerologAdapter")
}

// processorConfig holds configuration for creating processors
type processorConfig struct {
	scope         string // "system" or "organization"
	scopeID       string // Empty for system, orgID for organization
	config        *encTypes.EncryptionConfig
	db            *mongo.Database
	encryptionKey []byte
}

// StorageAdapter adapts between store.Store and types.Storage interfaces
type StorageAdapter struct {
	store interfaces.DEKStore
}

func NewStorageAdapter(store interfaces.DEKStore) *StorageAdapter {
	return &StorageAdapter{store: store}
}

// Implement types.Storage interface
func (a *StorageAdapter) Get(ctx context.Context, key string, value interface{}) error {
	return nil
}

func (a *StorageAdapter) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return nil
}

func (a *StorageAdapter) Delete(ctx context.Context, key string) error {
	return nil
}

func (a *StorageAdapter) Clear(ctx context.Context) error {
	return nil
}

func (a *StorageAdapter) GetStats(ctx context.Context) encTypes.CacheStats {
	return encTypes.CacheStats{
		Size:   0,
		Hits:   0,
		Misses: 0,
	}
}

// ClearExpiredKeys implements the Storage interface
func (a *StorageAdapter) ClearExpiredKeys(ctx context.Context) (int, error) {
	// This is a no-op adapter that doesn't store anything with TTL
	return 0, nil
}

// Implement store.Store interface by delegating to underlying store
func (a *StorageAdapter) GetDEK(ctx context.Context, scope, id string) (*encTypes.DEKInfo, error) {
	return a.store.GetDEK(ctx, scope, id)
}

func (a *StorageAdapter) StoreDEK(ctx context.Context, dek *encTypes.DEKInfo, scope, id string) error {
	return a.store.StoreDEK(ctx, dek, scope, id)
}

func (a *StorageAdapter) DeleteDEK(ctx context.Context, scope, id string) error {
	return a.store.DeleteDEK(ctx, scope, id)
}

func (a *StorageAdapter) ListDEKs(ctx context.Context, scope string) ([]*encTypes.DEKInfo, error) {
	return a.store.ListDEKs(ctx, scope)
}

// createSharedComponents creates common components used by both system and organization processors
func createSharedComponents(cfg *processorConfig) (kms.Provider, interfaces.AuditLogger, interfaces.Storage, interfaces.DEKService, error) {
	// Create audit logger (metrics support pending)
	auditLogger, err := createAuditLogger(cfg.scope, cfg.scopeID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Create KMS provider if encryption is enabled
	provider, err := createKMSProvider(cfg.config)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create cache storage with validation
	store, err := createCacheStorage(cfg.config)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create MongoDB store
	mongoStore := dekstore.NewMongoDBStore(cfg.db)

	// Create DEK service with proper key handling
	dekService, err := createDEKService(cfg.config, provider, auditLogger, mongoStore, store, cfg.encryptionKey)
	if err != nil {
		return nil, auditLogger, store, nil, err
	}

	return provider, auditLogger, store, dekService, nil
}

func createAuditLogger(scope, scopeID string) (interfaces.AuditLogger, error) {
	logger := audit.NewStdoutAuditLogger()

	// Create initial audit event to log scope information
	ctx := context.Background()
	event := &encTypes.AuditEvent{
		EventType: "initialization",
		Operation: "create_logger",
		Status:    "success",
		Context: map[string]string{
			"scope":    scope,
			"scope_id": scopeID,
		},
	}

	if err := logger.LogEvent(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to log initial audit event: %w", err)
	}

	return logger, nil
}

func createKMSProvider(config *encTypes.EncryptionConfig) (kms.Provider, error) {
	if !config.Enabled || config.Provider == "" {
		return nil, nil
	}

	// Create credentials map
	var credentials map[string]interface{}
	if config.Credentials != nil {
		credentials = make(map[string]interface{})
		switch config.Provider {
		case encTypes.ProviderAWS:
			credentials["accessKeyId"] = config.Credentials.AccessKeyID
			credentials["secretAccessKey"] = config.Credentials.SecretAccessKey
			if config.Credentials.SessionToken != "" {
				credentials["sessionToken"] = config.Credentials.SessionToken
			}
		case encTypes.ProviderGCP:
			credentials["credentialsJson"] = config.Credentials.CredentialsJSON
		case encTypes.ProviderVault:
			credentials["token"] = config.Credentials.Token
		case encTypes.ProviderAzure:
			credentials["tenantId"] = config.Credentials.TenantID
			credentials["clientId"] = config.Credentials.ClientID
			credentials["clientSecret"] = config.Credentials.ClientSecret
		}
	}

	provider, err := kms.NewProvider(kms.Config{
		Type:         config.Provider,
		KeyID:        config.KeyID,
		Region:       config.Region,
		Credentials:  credentials,
		VaultAddress: config.VaultAddress,
		VaultMount:   config.VaultMount,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS provider: %w", err)
	}

	return provider, nil
}

func createCacheStorage(config *encTypes.EncryptionConfig) (interfaces.Storage, error) {
	if !config.Cache.Enabled {
		return nil, nil
	}

	// Validate TTL
	if config.Cache.TTL < 1 {
		return nil, fmt.Errorf("cache TTL must be at least 1 minute")
	}

	// Create memory adapter with default configuration
	store := storage.NewMemoryAdapter()

	return store, nil
}

func createDEKService(config *encTypes.EncryptionConfig, provider kms.Provider, auditLogger interfaces.AuditLogger, store interfaces.DEKStore, cacheStore interfaces.Storage, encryptionKey []byte) (interfaces.DEKService, error) {
	// Create DEK service
	dekService, err := dek.NewService(config, provider, auditLogger, store, cacheStore, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create DEK service: %w", err)
	}

	return dekService, nil
}
