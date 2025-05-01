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
	"strings"
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
	// Removed scope and id fields - context should provide this info
}

// NewFieldService creates a new field encryption service
// NewFieldService creates a new field encryption service. Scope and ID are determined from context during operations.
func NewFieldService(dekSvc interfaces.DEKService, logger interfaces.AuditLogger) interfaces.FieldService {
	log.Debug().
		Bool("hasDEKService", dekSvc != nil).
		Bool("hasLogger", logger != nil).
		Msg("Creating new field service")

	// If DEK service is nil, create a no-op service that only handles plaintext
	if dekSvc == nil {
		log.Trace().
			Msg("Creating no-op field service (DEK service is nil)")
		// No-op service still needs logger, but no scope/id stored
		return &fieldService{
			logger: logger,
		}
	}

	svc := &fieldService{
		dekService: dekSvc,
		logger:     logger,
		// scope and id removed
	}

	log.Debug().
		// Removed scope/id logging from constructor message
		Msg("Field service created successfully")

	return svc
}

// GenerateSearchHash creates a consistent hash for searchable encrypted fields.
// It uses HMAC-SHA256 with a provided secret key.
func generateSearchHash(value string, searchKey []byte) string {
	if len(searchKey) == 0 {
		log.Error().Msg("Search key is empty, cannot generate search hash.")
		return "" // Return empty if key is missing
	}
	if value == "" {
		return "" // Return empty if value is empty
	}

	// Normalize: Convert to lowercase and trim whitespace
	normalizedValue := strings.ToLower(strings.TrimSpace(value))
	if normalizedValue == "" {
		log.Warn().Str("originalValue", value).Msg("Value became empty after normalization, returning empty search hash.")
		return "" // Return empty if value was only whitespace
	}

	h := hmac.New(sha256.New, searchKey)
	// Use the normalized value for hashing
	h.Write([]byte(normalizedValue))
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

	// Add scope information extracted from context
	scope, scopeID := getScopeAndIDFromContext(ctx) // Use package-level helper
	event.Context[string(audit.KeyScope)] = scope
	if scopeID != "" {
		// Add appropriate ID based on scope
		if scope == "organization" {
			event.Context[string(audit.KeyOrgID)] = scopeID
		} else if scope == "user" { // Assuming "user" scope might exist
			event.Context[string(audit.KeyUserID)] = scopeID
		}
		// Add other scope ID keys if necessary
	}

	return event
}

// buildAAD constructs the Additional Authenticated Data (AAD) string
// using the full context: scope, id, collection, fieldName, and version.
func (s *fieldService) buildAAD(ctx context.Context, version uint32) ([]byte, error) {
	// Extract scope, scopeID, collection, and fieldName from context using helpers
	scope, scopeID := getScopeAndIDFromContext(ctx)                 // Use package-level helper
	collection, _, fieldName, _ := extractFieldInfoFromContext(ctx) // Use existing helper

	// Log extracted/passed values for debugging AAD issues
	log.Trace().
		Str("scope", scope).
		Str("scopeID", scopeID).
		Str("collection", collection).
		Str("fieldName", fieldName).
		Uint32("version", version).
		Msg("Building AAD with extracted context")

	// Validate that we extracted necessary context
	// Note: collectionName and fieldName are passed explicitly, so primarily check scope/scopeID
	if scope == "unknown" || collection == "unknown" || fieldName == "unknown" || (scope == "organization" && scopeID == "") { // Added check for org scopeID
		log.Error().
			Str("scope", scope).
			Str("scopeID", scopeID). // Use extracted scopeID
			Str("extractedCollection", collection).
			Str("extractedFieldName", fieldName).
			Uint32("version", version).
			Msgf("Failed to build AAD: Missing required context (scope=%s, scopeID=%s, collection=%s, fieldName=%s) for AAD construction", scope, scopeID, collection, fieldName) // Use Msgf for formatting
		return nil, fmt.Errorf("missing required context (scope=%s, scopeID=%s, collection=%s, fieldName=%s) for AAD construction", scope, scopeID, collection, fieldName)
	}

	// Validate that we extracted necessary context
	// Allow "unknown" only if explicitly permitted by configuration or design (currently enforcing)
	// Construct AAD string using a consistent format (key=value, sorted keys recommended)
	// Use extracted scope and scopeID
	aadString := fmt.Sprintf("collection=%s:field=%s:id=%s:scope=%s:v=%d",
		collection, fieldName, scopeID, scope, version)

	log.Debug().Str("aad", aadString).Msg("Constructed AAD")
	return []byte(aadString), nil
}

// Encrypt encrypts a field value if encryption is enabled
func (s *fieldService) Encrypt(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
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

	// Get the current DEK status using scope/ID from context
	scope, scopeID := getScopeAndIDFromContext(ctx) // Use package-level helper
	dekStatus, err := s.dekService.GetDEKStatus(ctx, scope, scopeID)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_dek_status: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK status for scope %s/%s: %w", scope, scopeID, err)
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
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error and update audit event status
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during encryption")
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_build_aad: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to build AAD for encryption: %w", err)
	}

	// Get active DEK using scope/ID from context
	dek, dekErr := s.dekService.GetActiveDEK(ctx, scope, scopeID)
	if dekErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_active_dek: %v", dekErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get active DEK: %w", dekErr)
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
	block, cipherErr := aes.NewCipher(dek)
	if cipherErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", cipherErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", cipherErr)
	}

	// Create GCM mode
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", gcmErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, nonceErr := rand.Read(nonce); nonceErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_generate_nonce: %v", nonceErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to generate nonce: %w", nonceErr)
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

	// Get DEK Info using scope/ID from context
	scope, scopeID := getScopeAndIDFromContext(ctx) // Use package-level helper
	dekInfo, err := s.dekService.GetInfo(ctx, scope, scopeID)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_dek_info: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK info for scope %s/%s: %w", scope, scopeID, err)
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

	// Build AAD using the version stored in the field and the context
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error and update audit event status
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during decryption")
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_build_aad: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to build AAD for decryption: %w", err)
	}

	// Get DEK for version
	key, err := s.dekService.UnwrapDEK(ctx, version)
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
	block, cipherErr := aes.NewCipher(key)
	if cipherErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", cipherErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", cipherErr)
	}

	// Create GCM mode
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", gcmErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	// Decrypt the data
	plaintextBytes, openErr := gcm.Open(nil, nonce, ciphertext, aad)
	if openErr != nil {
		// If we have plaintext, we can still proceed
		if field.Plaintext != "" {
			log.Warn().Err(openErr).Msg("Failed to decrypt data but plaintext available")
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
			auditEvent.Context["error"] = fmt.Sprintf("failed_decrypt: %v", openErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to decrypt data: %w", openErr)
	}

	// Update field with decrypted value
	field.Plaintext = string(plaintextBytes)
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

	// Get DEK status using scope/ID from context
	scope, scopeID := getScopeAndIDFromContext(ctx) // Use package-level helper
	systemStatus, err := s.dekService.GetDEKStatus(ctx, scope, scopeID)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = err.Error()
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK status for scope %s/%s: %w", scope, scopeID, err)
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

	// Additional authenticated data (AAD) includes version for integrity
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error and update audit event status
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during searchable encryption")
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_build_aad: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to build AAD for searchable encryption: %w", err)
	}

	// Get DEK for encryption using scope/ID from context
	dek, dekErr := s.dekService.GetActiveDEK(ctx, scope, scopeID) // Use extracted scope/ID
	if dekErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_active_dek: %v", dekErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get active DEK: %w", dekErr)
	}

	// Create AES cipher
	block, cipherErr := aes.NewCipher(dek)
	if cipherErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", cipherErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", cipherErr)
	}

	// Create GCM mode
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", gcmErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, nonceErr := rand.Read(nonce); nonceErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_generate_nonce: %v", nonceErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to generate nonce: %w", nonceErr)
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

	// Get DEK Info using scope/ID from context
	scope, scopeID := getScopeAndIDFromContext(ctx) // Use package-level helper
	dekInfo, err := s.dekService.GetInfo(ctx, scope, scopeID)
	if err != nil {
		return fmt.Errorf("failed to get DEK info for scope %s/%s: %w", scope, scopeID, err)
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

	// Get DEK for version using scope/ID from context
	key, err := s.dekService.UnwrapDEK(ctx, version) // UnwrapDEK itself uses context for AAD
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
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	// Additional authenticated data (AAD) includes version for integrity
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error - might not have audit event here, log directly
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during verification")
		return fmt.Errorf("failed to build AAD for verification: %w", err)
	}

	// Attempt to decrypt to verify integrity
	_, openErr := gcm.Open(nil, nonce, ciphertext, aad)
	if openErr != nil {
		return fmt.Errorf("failed to verify field: %w", openErr)
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

// Helper to get scope and scopeID from context (package level)
func getScopeAndIDFromContext(ctx context.Context) (scope string, scopeID string) {
	scope = ""   // Default to empty, let buildAAD enforce presence
	scopeID = "" // Default

	if val := ctx.Value(audit.KeyScope); val != nil {
		if str, ok := val.(string); ok && str != "" {
			scope = str
		}
	}

	// Extract OrgID specifically if scope is organization
	if scope == "organization" {
		if val := ctx.Value(audit.KeyOrgID); val != nil {
			if str, ok := val.(string); ok && str != "" {
				scopeID = str
			}
		}
	}
	// Add logic for other scopes like "user" if needed

	return scope, scopeID
}
