package dbencryption

import (
	"context"
	"fmt"
	"time"

	"github.com/root-sector-ltd-and-co-kg/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector-ltd-and-co-kg/multi-payment-gateway-module-encryption/kms"
	encTypes "github.com/root-sector-ltd-and-co-kg/multi-payment-gateway-module-encryption/types"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// kmsProviderAdapter adapts kms.Provider to dek.KMSServiceGetter
type kmsProviderAdapter struct {
	provider kms.Provider
}

// GetKMSProvider implements dek.KMSServiceGetter by returning the embedded provider.
func (a *kmsProviderAdapter) GetKMSProvider(ctx context.Context, scope string, orgID string) (kms.Provider, error) {
	// This adapter assumes the provider is already initialized and valid for the context.
	// It doesn't need to fetch based on scope/orgID here.
	return a.provider, nil
}

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
