// Package audit provides audit logging functionality for encryption operations
package audit

// ContextKey is a custom type for context keys to avoid collisions
type ContextKey string

// Context keys for encryption operations
const (
	// Core context keys
	KeyScope      ContextKey = "scope"      // system or organization
	KeyCollection ContextKey = "collection" // collection being operated on
	KeyFieldName  ContextKey = "fieldName"  // field being encrypted/decrypted
	KeyFieldType  ContextKey = "fieldType"  // type of field being operated on
	KeyDEKID      ContextKey = "dekId"      // DEK identifier
	KeyOrgID      ContextKey = "orgId"      // Organization ID if applicable
	KeyError      ContextKey = "error"      // Error message if operation failed
	KeyRecordID   ContextKey = "recordId"   // Record identifier

	// User context keys
	KeyUserID    ContextKey = "userId"    // User identifier
	KeyUserEmail ContextKey = "userEmail" // User email
	KeyOperation ContextKey = "operation" // Operation being performed
)

// GetContextKey returns the ContextKey type for a given string
func GetContextKey(key string) ContextKey {
	return ContextKey(key)
}
