package field

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/root-sector/multi-payment-gateway-module-encryption/audit"
	"github.com/root-sector/multi-payment-gateway-module-encryption/interfaces"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
)

var (
	// ErrEncryptionDisabled indicates that encryption is not enabled
	ErrEncryptionDisabled = fmt.Errorf("encryption is disabled")
	// ErrMissingSearchKey indicates that a search key is required for searchable encryption
	ErrMissingSearchKey = fmt.Errorf("search key is required for searchable encryption")
)

// fieldService implements the interfaces.FieldService interface
type fieldService struct {
	dekService interfaces.DEKService
	logger     interfaces.AuditLogger
	stats      types.FieldStats
	scope      string // "system" or "organization"
	id         string // User ID when scope is "user", Organization ID when scope is "organization"
}

// NewFieldService creates a new field encryption service
func NewFieldService(dekSvc interfaces.DEKService, logger interfaces.AuditLogger, scope string, id string) interfaces.FieldService {
	log.Debug().
		Str("scope", scope).
		Str("id", id).
		Bool("hasDEKService", dekSvc != nil).
		Bool("hasLogger", logger != nil).
		Msg("Creating new field service")

	// If DEK service is nil, create a no-op service that only handles plaintext
	if dekSvc == nil {
		log.Trace().
			Str("scope", scope).
			Str("id", id).
			Msg("Creating no-op field service (DEK service is nil)")
		return &fieldService{
			logger: logger,
			scope:  scope,
			id:     id,
		}
	}

	svc := &fieldService{
		dekService: dekSvc,
		logger:     logger,
		scope:      scope,
		id:         id,
	}

	log.Debug().
		Str("scope", scope).
		Str("id", id).
		Msg("Field service created successfully")

	return svc
}

// generateSearchHash creates an HMAC-SHA256 hash of the value using the provided search key
func generateSearchHash(value string, searchKey []byte) string {
	h := hmac.New(sha256.New, searchKey)
	h.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Helper functions to extract info from context
func extractFieldInfoFromContext(ctx context.Context) (collection, recordID, fieldName, fieldType string) {
	if val, ok := ctx.Value(audit.KeyCollection).(string); ok {
		collection = val
	}
	if val, ok := ctx.Value(audit.KeyRecordID).(string); ok {
		recordID = val
	}
	if val, ok := ctx.Value(audit.KeyFieldName).(string); ok {
		fieldName = val
	}
	if val, ok := ctx.Value(audit.KeyFieldType).(string); ok {
		fieldType = val
	}
	return
}

func extractUserInfoFromContext(ctx context.Context) (email, userID, orgID, operation string) {
	if val, ok := ctx.Value(audit.KeyUserEmail).(string); ok {
		email = val
	}
	if val, ok := ctx.Value(audit.KeyUserID).(string); ok {
		userID = val
	}
	if val, ok := ctx.Value(audit.KeyOrgID).(string); ok {
		orgID = val
	}
	if val, ok := ctx.Value(audit.KeyOperation).(string); ok {
		operation = val
	}
	return
}

// createAuditEvent creates an audit event with proper context
func (s *fieldService) createAuditEvent(ctx context.Context, field *types.FieldEncrypted, eventType, operation string) *types.AuditEvent {
	event := audit.NewAuditEvent(eventType, operation, int(field.Version))

	// Extract context information
	collection, recordID, fieldName, fieldType := extractFieldInfoFromContext(ctx)
	email, userID, orgID, op := extractUserInfoFromContext(ctx)

	// Add context information
	if collection != "" {
		event.Context[string(audit.KeyCollection)] = collection
	}
	if recordID != "" {
		event.Context[string(audit.KeyRecordID)] = recordID
	}
	if fieldName != "" {
		event.Context[string(audit.KeyFieldName)] = fieldName
	}
	if fieldType != "" {
		event.Context[string(audit.KeyFieldType)] = fieldType
	}
	if email != "" {
		event.Context[string(audit.KeyUserEmail)] = email
	}
	if userID != "" {
		event.Context[string(audit.KeyUserID)] = userID
	}
	if orgID != "" {
		event.Context[string(audit.KeyOrgID)] = orgID
	}
	if op != "" {
		event.Context[string(audit.KeyOperation)] = op
	}

	// Add scope information
	event.Context[string(audit.KeyScope)] = s.scope
	if s.id != "" {
		if s.scope == "organization" {
			event.Context[string(audit.KeyOrgID)] = s.id
		} else if s.scope == "user" {
			event.Context[string(audit.KeyUserID)] = s.id
		}
	}

	return event
}

// Encrypt encrypts a field value if encryption is enabled
func (s *fieldService) Encrypt(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// Extract field information from context
	collection, recordID, fieldName, fieldType := extractFieldInfoFromContext(ctx)
	email, userID, orgID, operation := extractUserInfoFromContext(ctx)

	// Add context to audit event if available
	if collection != "" || recordID != "" || fieldName != "" || fieldType != "" {
		ctx = audit.WithContext(ctx, collection, fieldName, fieldType)
		if recordID != "" {
			ctx = audit.WithRecordID(ctx, recordID)
		}
		if email != "" || userID != "" {
			ctx = audit.WithUserContext(ctx, userID, email)
		}
		if orgID != "" {
			ctx = audit.WithOrganization(ctx, orgID)
		}
		if operation != "" {
			ctx = audit.WithOperation(ctx, operation)
		}
	}

	// Create audit event
	auditEvent := s.createAuditEvent(ctx, field, audit.EventTypeFieldEncrypt, audit.OperationEncrypt)

	// Always update timestamp
	field.UpdatedAt = time.Now().UTC()

	// If there's no plaintext, nothing to encrypt
	if field.Plaintext == "" {
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "no_plaintext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// If DEK service is nil, encryption is disabled - just keep plaintext
	if s.dekService == nil {
		// Clear any existing encryption fields to ensure consistency
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "encryption_disabled"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Get the current DEK status to determine the active version
	dekStatus, err := s.dekService.GetStatus(ctx, s.scope, s.id)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_dek_status: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK status: %w", err)
	}

	// If DEK is not active, operate in plaintext mode
	if !dekStatus.Active {
		// Clear any existing encryption fields
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "dek_not_active"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Set version from the current active DEK version
	field.Version = uint32(dekStatus.Version)
	auditEvent.DEKVersion = dekStatus.Version

	// Additional authenticated data (AAD) includes version for integrity
	aad := []byte(fmt.Sprintf("v%d", field.Version))

	// Get active DEK
	dek, err := s.dekService.GetActiveDEK(ctx, s.scope, s.id)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_active_dek: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get active DEK: %w", err)
	}

	// If no key is returned, keep plaintext
	if dek == nil {
		// Clear any existing encryption fields
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "no_active_dek"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Create AES cipher
	block, err := aes.NewCipher(dek)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_generate_nonce: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext with AAD
	ciphertext := gcm.Seal(nil, nonce, []byte(field.Plaintext), aad)

	// Update field with encrypted values
	field.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	field.IV = base64.StdEncoding.EncodeToString(nonce)
	field.Plaintext = "" // Clear plaintext after successful encryption

	// Update stats
	atomic.AddUint64(&s.stats.TotalEncrypts, 1)
	now := time.Now().UTC()
	s.stats.LastEncryptTime = now
	s.stats.LastOpTime = now

	// REMOVED: Redundant audit log. Factory logs this event.
	// if s.logger != nil {
	// 	auditEvent.Status = audit.StatusSuccess
	// 	s.logger.LogEvent(ctx, auditEvent)
	// }

	return nil
}

// Decrypt decrypts a field value if it is encrypted
func (s *fieldService) Decrypt(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// Extract field information from context
	collection, recordID, fieldName, fieldType := extractFieldInfoFromContext(ctx)
	email, userID, orgID, operation := extractUserInfoFromContext(ctx)

	// Add context to audit event if available
	if collection != "" || recordID != "" || fieldName != "" || fieldType != "" {
		ctx = audit.WithContext(ctx, collection, fieldName, fieldType)
		if recordID != "" {
			ctx = audit.WithRecordID(ctx, recordID)
		}
		if email != "" || userID != "" {
			ctx = audit.WithUserContext(ctx, userID, email)
		}
		if orgID != "" {
			ctx = audit.WithOrganization(ctx, orgID)
		}
		if operation != "" {
			ctx = audit.WithOperation(ctx, operation)
		}
	}

	// Create audit event
	auditEvent := s.createAuditEvent(ctx, field, audit.EventTypeFieldDecrypt, audit.OperationDecrypt)

	// If there's no ciphertext, nothing to decrypt
	if field.Ciphertext == "" {
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "no_ciphertext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// If DEK service is nil, encryption is disabled
	if s.dekService == nil {
		// If we have ciphertext but no DEK service, we can't decrypt
		// Return error only if we don't have plaintext
		if field.Plaintext == "" {
			if s.logger != nil {
				auditEvent.Status = audit.StatusFailed
				auditEvent.Context["error"] = "encryption_disabled_no_plaintext"
				s.logger.LogEvent(ctx, auditEvent)
			}
			return fmt.Errorf("cannot decrypt field: encryption is disabled and no plaintext available")
		}
		// If we have plaintext, just update timestamp and return
		field.UpdatedAt = time.Now().UTC()
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "has_plaintext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Create a Version struct for unwrapping
	dekInfo, err := s.dekService.GetInfo(ctx, s.scope, s.id)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_dek_info: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK info: %w", err)
	}

	// Find the correct version
	var version *types.DEKVersion
	for _, v := range dekInfo.Versions {
		if v.Version == int(field.Version) {
			version = &v
			break
		}
	}

	if version == nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("dek_version_not_found: %d", field.Version)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("DEK version %d not found", field.Version)
	}

	// Create a specific context for unwrapping, ensuring correct scope and ID
	unwrapCtx := context.WithValue(ctx, audit.KeyScope, s.scope)
	if s.scope == "organization" && s.id != "" {
		unwrapCtx = context.WithValue(unwrapCtx, audit.KeyOrgID, s.id)
	}

	// Get DEK for version using the specific unwrap context
	key, err := s.dekService.UnwrapDEK(unwrapCtx, version)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_unwrap_dek: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK: %w", err)
	}

	// Decode base64 values
	ciphertext, err := base64.StdEncoding.DecodeString(field.Ciphertext)
	if err != nil {
		// If we have plaintext, we can still proceed
		if field.Plaintext != "" {
			log.Warn().Err(err).Msg("Failed to decode ciphertext but plaintext available")
			field.UpdatedAt = time.Now().UTC()
			if s.logger != nil {
				auditEvent.Status = audit.StatusSuccess
				auditEvent.Context["reason"] = "decode_failed_has_plaintext"
				s.logger.LogEvent(ctx, auditEvent)
			}
			return nil
		}
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_decode_ciphertext: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(field.IV)
	if err != nil {
		// If we have plaintext, we can still proceed
		if field.Plaintext != "" {
			log.Warn().Err(err).Msg("Failed to decode IV but plaintext available")
			field.UpdatedAt = time.Now().UTC()
			if s.logger != nil {
				auditEvent.Status = audit.StatusSuccess
				auditEvent.Context["reason"] = "decode_iv_failed_has_plaintext"
				s.logger.LogEvent(ctx, auditEvent)
			}
			return nil
		}
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_decode_iv: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Additional authenticated data (AAD) includes version for integrity
	aad := []byte(fmt.Sprintf("v%d", field.Version))

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// If we have plaintext, we can still proceed
		if field.Plaintext != "" {
			log.Warn().Err(err).Msg("Failed to decrypt data but plaintext available")
			field.UpdatedAt = time.Now().UTC()
			if s.logger != nil {
				auditEvent.Status = audit.StatusSuccess
				auditEvent.Context["reason"] = "decrypt_failed_has_plaintext"
				s.logger.LogEvent(ctx, auditEvent)
			}
			return nil
		}
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_decrypt: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Update field with decrypted value
	field.Plaintext = string(plaintext)
	field.UpdatedAt = time.Now().UTC()

	// Update stats
	atomic.AddUint64(&s.stats.TotalDecrypts, 1)
	now := time.Now().UTC()
	s.stats.LastDecryptTime = now
	s.stats.LastOpTime = now

	// REMOVED: Redundant audit log. Factory logs this event.
	// if s.logger != nil {
	// 	auditEvent.Status = audit.StatusSuccess
	// 	s.logger.LogEvent(ctx, auditEvent)
	// }

	return nil
}

// EncryptSearchable encrypts a field value and generates a search hash
func (s *fieldService) EncryptSearchable(ctx context.Context, field *types.FieldEncrypted, searchKey string) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	if searchKey == "" {
		return ErrMissingSearchKey
	}

	// Extract field information from context
	collection, recordID, fieldName, fieldType := extractFieldInfoFromContext(ctx)
	email, userID, orgID, operation := extractUserInfoFromContext(ctx)

	// Add context to audit event if available
	if collection != "" || recordID != "" || fieldName != "" || fieldType != "" {
		ctx = audit.WithContext(ctx, collection, fieldName, fieldType)
		if recordID != "" {
			ctx = audit.WithRecordID(ctx, recordID)
		}
		if email != "" || userID != "" {
			ctx = audit.WithUserContext(ctx, userID, email)
		}
		if orgID != "" {
			ctx = audit.WithOrganization(ctx, orgID)
		}
		if operation != "" {
			ctx = audit.WithOperation(ctx, operation)
		}
	}

	// Create audit event
	auditEvent := s.createAuditEvent(ctx, field, audit.EventTypeFieldEncrypt, audit.OperationEncrypt)

	// Always update timestamp
	field.UpdatedAt = time.Now().UTC()

	// Generate HMAC-SHA256 search hash first
	if field.Plaintext != "" {
		field.SearchHash = generateSearchHash(field.Plaintext, []byte(searchKey))
	}

	// If DEK service is nil or encryption is disabled, just update timestamp and return
	if s.dekService == nil {
		// Clear any existing encryption fields to ensure consistency
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		// Log audit event
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["mode"] = "plaintext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Get system DEK info
	systemStatus, err := s.dekService.GetStatus(ctx, s.scope, s.id)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = err.Error()
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK status: %w", err)
	}

	// If no active DEK, operate in plaintext mode
	if !systemStatus.Active {
		// Clear any existing encryption fields
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		// Log audit event
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["mode"] = "plaintext_no_dek"
			s.logger.LogEvent(ctx, auditEvent)
		}

		return nil
	}

	// Set the field version to the current DEK version
	field.Version = uint32(systemStatus.Version)
	auditEvent.DEKVersion = systemStatus.Version

	// Get DEK for encryption
	dek, err := s.dekService.GetActiveDEK(ctx, s.scope, s.id)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = err.Error()
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get active DEK: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(dek)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = err.Error()
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = err.Error()
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = err.Error()
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Additional authenticated data (AAD) includes version for integrity
	aad := []byte(fmt.Sprintf("v%d", field.Version))

	// Encrypt plaintext with AAD
	ciphertext := gcm.Seal(nil, nonce, []byte(field.Plaintext), aad)

	// Update field with encrypted values
	field.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	field.IV = base64.StdEncoding.EncodeToString(nonce)
	field.Plaintext = "" // Clear plaintext after successful encryption

	// Update stats
	atomic.AddUint64(&s.stats.TotalEncrypts, 1)
	now := time.Now().UTC()
	s.stats.LastEncryptTime = now
	s.stats.LastOpTime = now

	// Log successful encryption
	if s.logger != nil {
		auditEvent.Status = audit.StatusSuccess
		s.logger.LogEvent(ctx, auditEvent)
	}

	return nil
}

// Match checks if a plaintext value matches an encrypted searchable field
func (s *fieldService) Match(ctx context.Context, field *types.FieldEncrypted, value string, searchKey string) (bool, error) {
	if field == nil {
		return false, fmt.Errorf("field is nil")
	}

	if searchKey == "" {
		return false, ErrMissingSearchKey
	}

	// If field has no search hash, return false
	if field.SearchHash == "" {
		return false, nil
	}

	// Generate HMAC-SHA256 hash of search value
	searchHash := generateSearchHash(value, []byte(searchKey))

	// Compare hashes
	return searchHash == field.SearchHash, nil
}

// Verify verifies the integrity of an encrypted field
func (s *fieldService) Verify(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// Create audit event
	event := s.createAuditEvent(ctx, field, "verify", "field_verify")

	// Log start event
	if err := s.logger.LogEvent(ctx, event); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	defer func() {
		// Always update event status at the end
		event.Status = "completed"
		event.Timestamp = time.Now().UTC()
		if err := s.logger.LogEvent(ctx, event); err != nil {
			fmt.Printf("Failed to log audit event: %v\n", err)
		}
	}()

	// Check required fields
	if field.Version == 0 {
		return fmt.Errorf("version is required")
	}
	if field.Ciphertext == "" {
		return fmt.Errorf("ciphertext is required")
	}
	if field.IV == "" {
		return fmt.Errorf("IV is required")
	}

	// Create a Version struct for unwrapping
	dekInfo, err := s.dekService.GetInfo(ctx, s.scope, s.id)
	if err != nil {
		return fmt.Errorf("failed to get DEK info: %w", err)
	}

	// Find the correct version
	var version *types.DEKVersion
	for _, v := range dekInfo.Versions {
		if v.Version == int(field.Version) {
			version = &v
			break
		}
	}

	if version == nil {
		return fmt.Errorf("DEK version %d not found", field.Version)
	}

	// Get DEK for version
	key, err := s.dekService.UnwrapDEK(ctx, version)
	if err != nil {
		return fmt.Errorf("failed to get DEK: %w", err)
	}

	// Decode base64 values
	ciphertext, err := base64.StdEncoding.DecodeString(field.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(field.IV)
	if err != nil {
		return fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode with default tag size (16 bytes)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Additional authenticated data (AAD) includes version for integrity
	aad := []byte(fmt.Sprintf("v%d", field.Version))

	// Attempt to decrypt to verify integrity
	_, err = gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return fmt.Errorf("failed to verify field: %w", err)
	}

	return nil
}

// GetStats returns statistics about field encryption operations
func (s *fieldService) GetStats(ctx context.Context) (*types.FieldStats, error) {
	// Convert internal stats to the return type
	return &types.FieldStats{
		TotalEncrypts:   s.stats.TotalEncrypts,
		TotalDecrypts:   s.stats.TotalDecrypts,
		LastEncryptTime: s.stats.LastEncryptTime,
		LastDecryptTime: s.stats.LastDecryptTime,
		LastOpTime:      s.stats.LastOpTime,
	}, nil
}

// ValidateAndCleanupEncryptedField validates that the ciphertext decrypts to the plaintext
// and removes the plaintext if validation is successful
func (s *fieldService) ValidateAndCleanupEncryptedField(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// If there's no ciphertext, nothing to validate
	if field.Ciphertext == "" {
		return fmt.Errorf("no ciphertext to validate")
	}

	// Create a validation decorator
	validateFunc := func(ctx context.Context, e *types.FieldEncrypted) error {
		// Try to decrypt using our decrypt method
		return s.Decrypt(ctx, e)
	}

	// Use the validate function
	if err := validateEncryptedField(ctx, field, validateFunc); err != nil {
		return err
	}

	// Validation successful
	return nil
}

// validateEncryptedField is a helper function to validate an encrypted field
func validateEncryptedField(ctx context.Context, field *types.FieldEncrypted, decryptFunc func(context.Context, *types.FieldEncrypted) error) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// If there's no ciphertext, nothing to validate
	if field.Ciphertext == "" {
		return fmt.Errorf("no ciphertext to validate")
	}

	// Store original plaintext for validation
	originalPlaintext := field.Plaintext

	// Try to decrypt the field
	if err := decryptFunc(ctx, field); err != nil {
		// Restore original plaintext since decryption failed
		field.Plaintext = originalPlaintext
		return fmt.Errorf("failed to decrypt field for validation: %w", err)
	}

	// Validate decrypted value matches original plaintext
	if field.Plaintext != originalPlaintext {
		// Restore original plaintext since validation failed
		field.Plaintext = originalPlaintext
		return fmt.Errorf("decrypted value does not match original plaintext")
	}

	// Clear plaintext after successful validation
	field.Plaintext = ""
	return nil
}

// ValidateAndCleanupEncryptedFields validates and cleans up multiple encrypted fields
func (s *fieldService) ValidateAndCleanupEncryptedFields(ctx context.Context, fields ...*types.FieldEncrypted) error {
	for _, field := range fields {
		if err := s.ValidateAndCleanupEncryptedField(ctx, field); err != nil {
			return fmt.Errorf("failed to validate and cleanup field: %w", err)
		}
	}
	return nil
}
