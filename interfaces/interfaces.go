// Package interfaces defines all service interfaces for the application.
// IMPORTANT: This is the single source of truth for service interfaces.
// Do not define interfaces in other files.
package interfaces

import (
	"context"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
)

// Cache Interfaces
// Cache defines the interface for cache operations
type Cache interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string, dest interface{}) error
	Delete(ctx context.Context, key string) error
	Keys(ctx context.Context, pattern string) ([]string, error)
}

// Storage defines the interface for cache storage backends
type Storage interface {
	Get(ctx context.Context, key string, value interface{}) error
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	// ClearExpiredKeys removes only expired keys and returns the count of removed entries
	ClearExpiredKeys(ctx context.Context) (int, error)
}

// Encryption Interfaces
// DEKService defines the interface for Data Encryption Key (DEK) management
type DEKService interface {
	// Base service methods
	Initialize(ctx context.Context) error
	GetAuditLogger() interface{}
	GetTaskProcessor() interface{}

	// Scoped operations
	GetInfo(ctx context.Context, scope string, id string) (*types.DEKInfo, error)
	GetDEKStatus(ctx context.Context, scope string, id string) (*types.DEKStatus, error)
	GetDEKStats(ctx context.Context, scope string, id string) (*types.DEKStats, error)
	Create(ctx context.Context, scope string, id string) error
	Rotate(ctx context.Context, scope string, id string) error
	Restore(ctx context.Context, scope string, id string) error

	// Low-level DEK operations
	CreateDEK(ctx context.Context, scope string, orgID string) (*types.DEKInfo, error)
	DeleteDEK(ctx context.Context, scope string, orgID string) error
	UnwrapDEK(ctx context.Context, version *types.DEKVersion, scope string, orgID string) ([]byte, error)
	RotateDEK(ctx context.Context, scope string, orgID string, force bool) (*types.DEKInfo, error)
	GetActiveDEK(ctx context.Context, scope string, orgID string) ([]byte, error)
	InvalidateCache(ctx context.Context, scope string, scopeID string) error // Added for cache invalidation

	// Placeholder methods for potential future interface consolidation (from old Service interface)
	GetScopedFieldService(ctx context.Context) (FieldService, error)
}

// ConfigGetter defines the interface for retrieving encryption configuration based on scope.
// This is typically implemented by a backend service that wraps the actual config storage.
type ConfigGetter interface {
	GetEncryptionConfig(ctx context.Context, scope string, scopeID string) (*types.EncryptionConfig, error)
}

// KMS Interfaces
// KMSProvider defines the interface for KMS providers
type KMSProvider interface {
	// GetWrapper returns the underlying KMS wrapper
	GetWrapper() wrapping.Wrapper

	// Test performs a test encryption/decryption
	Test(ctx context.Context) error

	// HealthCheck performs a comprehensive health check
	HealthCheck(ctx context.Context) error

	// GetLastHealthCheckError returns the last health check error
	GetLastHealthCheckError() error
}

// SymmetricEncryptor defines the interface for encrypting KMS credential values
type SymmetricEncryptor interface {
	// Encrypt encrypts a KMS credential value
	Encrypt(data string) (string, error)
	// Decrypt decrypts a KMS credential value
	Decrypt(data string) (string, error)
}

// CredentialsManager defines the interface for managing KMS provider credentials
type CredentialsManager interface {
	// EncryptCredentials encrypts all sensitive fields in KMS provider credentials
	EncryptCredentials(config *types.EncryptionConfig) error
	// DecryptCredentials decrypts all sensitive fields in KMS provider credentials
	DecryptCredentials(config *types.EncryptionConfig) error
}

// Store Interfaces
// DEKStore defines the interface for DEK storage
type DEKStore interface {
	// GetDEK retrieves a DEK by ID and scope
	GetDEK(ctx context.Context, id string, scope string) (*types.DEKInfo, error)

	// GetActiveDEK retrieves the active DEK for a scope
	GetActiveDEK(ctx context.Context, scope string, id string) (*types.DEKInfo, error)

	// StoreDEK stores a DEK
	StoreDEK(ctx context.Context, dek *types.DEKInfo, scope string, id string) error

	// DeleteDEK deletes a DEK
	DeleteDEK(ctx context.Context, id string, scope string) error

	// ListDEKs lists all DEKs for a scope
	ListDEKs(ctx context.Context, scope string) ([]*types.DEKInfo, error)
}

// Audit Interfaces
// AuditLogger defines the interface for audit logging
type AuditLogger interface {
	// Printf provides basic logging functionality
	Printf(format string, v ...interface{})

	// LogEvent logs an audit event
	LogEvent(ctx context.Context, event *types.AuditEvent) error

	// GetEvents retrieves audit events based on filters
	GetEvents(ctx context.Context, filters map[string]interface{}) ([]*types.AuditEvent, error)
}

// Field Encryption Interfaces
// Processor defines the interface for batch field processing
type Processor interface {
	// Process starts processing tasks
	Process(ctx context.Context) error

	// GetStatus returns the current processor status
	GetStatus(ctx context.Context) (*types.BatchFieldProcessor, error)

	// CancelTask cancels a specific task
	//CancelTask(ctx context.Context, taskID string) error

	// GetTaskStatus returns the status of a specific task
	//GetTaskStatus(ctx context.Context, taskID string) (*Task, error)

	// CreateTask creates a new encryption task
	//CreateTask(ctx context.Context, taskType Type, scope Scope, collection string, metadata map[string]interface{}) (*Task, error)

	// ListTasks returns a list of tasks with optional filters
	// ListTasks(ctx context.Context, filter map[string]interface{}) ([]*Task, error)

	// // GetTask retrieves a task by filter
	// GetTask(ctx context.Context, filter map[string]interface{}) (*Task, error)

	// // DeleteTask deletes a task by ID
	// DeleteTask(ctx context.Context, taskID string) error

	// Stop gracefully stops processing tasks
	Stop(ctx context.Context) error

	// Resume resumes processing tasks after a stop
	Resume(ctx context.Context) error

	// Reset resets the processor state
	Reset(ctx context.Context) error
}

// Service defines the interface for field encryption operations
type FieldService interface {
	// Encrypt encrypts a field value if encryption is enabled
	// It uses envelope encryption where the data is encrypted with a DEK,
	// and the DEK is encrypted (wrapped) by a KMS master key
	Encrypt(ctx context.Context, field *types.FieldEncrypted) error

	// Decrypt decrypts a field value if it is encrypted
	// It first unwraps the DEK using KMS and then decrypts the field value
	Decrypt(ctx context.Context, field *types.FieldEncrypted) error

	// Verify verifies that a field value is properly encrypted
	// It checks the version, ciphertext, and IV fields
	Verify(ctx context.Context, field *types.FieldEncrypted) error

	// EncryptSearchable encrypts a field value and generates a search hash
	// The search hash is a deterministic hash of the plaintext value
	// searchKey is required for generating the search hash
	EncryptSearchable(ctx context.Context, field *types.FieldEncrypted, searchKey string) error

	// Match checks if a plaintext value matches an encrypted searchable field
	// It compares the hash of the plaintext value with the stored search hash
	// searchKey must be the same key used to generate the search hash
	Match(ctx context.Context, field *types.FieldEncrypted, value string, searchKey string) (bool, error)

	// ValidateAndCleanupEncryptedField validates that the ciphertext decrypts to the plaintext
	// and removes the plaintext if validation is successful
	ValidateAndCleanupEncryptedField(ctx context.Context, field *types.FieldEncrypted) error

	// ValidateAndCleanupEncryptedFields validates and cleans up multiple encrypted fields
	ValidateAndCleanupEncryptedFields(ctx context.Context, fields ...*types.FieldEncrypted) error
}
