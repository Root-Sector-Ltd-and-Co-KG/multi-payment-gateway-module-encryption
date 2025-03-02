// Package audit provides audit logging functionality for encryption operations
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// Context keys
const (
	contextKeyCollection contextKey = "collection"
	contextKeyRecordID   contextKey = "record_id"
	contextKeyFieldName  contextKey = "field_name"
	contextKeyFieldType  contextKey = "field_type"
	contextKeyUserID     contextKey = "user_id"
	contextKeyOrgID      contextKey = "org_id"
	contextKeyDEKID      contextKey = "dek_id"
	contextKeyEmail      contextKey = "email"
	contextKeyOperation  contextKey = "operation_details"
	contextKeyAuthEmail  contextKey = "auth_email"
)

// Constants for event types and operations
const (
	// Event types
	EventTypeFieldEncrypt = "field.encrypt"
	EventTypeFieldDecrypt = "field.decrypt"
	EventTypeDEKRotate    = "dek.rotate"
	EventTypeDEKCreate    = "dek.create"

	// Operations
	OperationEncrypt = "encrypt"
	OperationDecrypt = "decrypt"
	OperationRotate  = "rotate"
	OperationCreate  = "create"

	// Statuses
	StatusSuccess = "success"
	StatusFailed  = "failed"

	// Context keys
	ContextKeyScope      = "scope"
	ContextKeySystem     = "system"
	ContextKeyFieldName  = "field_name"
	ContextKeyFieldType  = "field_type"
	ContextKeyRecordID   = "record_id"
	ContextKeyCollection = "collection"
	ContextKeyError      = "error"
	ContextKeyDEKID      = "dek_id"
	ContextKeyEmail      = "email"
	ContextKeyOperation  = "operation_details"
	ContextKeyUserID     = "user_id"
	ContextKeyOrgID      = "org_id"
	ContextKeyAuthEmail  = "auth_email"
)

// FieldOperation represents a field encryption/decryption operation
type FieldOperation struct {
	Collection string
	RecordID   string
	FieldName  string
	FieldType  string
	Email      string
	UserID     string
	OrgID      string
	DEKID      string
	Operation  string
	DEKVersion int
}

// StdoutAuditLogger implements Logger interface writing to stdout
type StdoutAuditLogger struct{}

// NewStdoutAuditLogger creates a new stdout audit logger
func NewStdoutAuditLogger() *StdoutAuditLogger {
	return &StdoutAuditLogger{}
}

// LogEvent logs an audit event to stdout with enhanced context information
func (l *StdoutAuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Ensure required fields
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Context == nil {
		event.Context = make(map[string]string)
	}

	// Use zerolog for audit logging
	logEvent := log.Debug().
		Str("audit_id", event.ID).
		Time("timestamp", event.Timestamp).
		Str("event_type", event.EventType).
		Str("operation", event.Operation).
		Str("status", event.Status).
		Int("dek_version", event.DEKVersion)

	// Add essential context fields
	if collection := event.Context[ContextKeyCollection]; collection != "" {
		logEvent = logEvent.Str("collection", collection)
	}
	if recordID := event.Context[ContextKeyRecordID]; recordID != "" {
		logEvent = logEvent.Str("record_id", recordID)
	}
	if fieldName := event.Context[ContextKeyFieldName]; fieldName != "" {
		logEvent = logEvent.Str("field_name", fieldName)
	}
	if fieldType := event.Context[ContextKeyFieldType]; fieldType != "" {
		logEvent = logEvent.Str("field_type", fieldType)
	}
	if userID := event.Context[ContextKeyUserID]; userID != "" {
		logEvent = logEvent.Str("user_id", userID)
	}
	if email := event.Context[ContextKeyEmail]; email != "" {
		logEvent = logEvent.Str("email", email)
	}
	if authEmail := event.Context[ContextKeyAuthEmail]; authEmail != "" {
		logEvent = logEvent.Str("auth_email", authEmail)
	}
	if orgID := event.Context[ContextKeyOrgID]; orgID != "" {
		logEvent = logEvent.Str("org_id", orgID)
	}
	if operation := event.Context[ContextKeyOperation]; operation != "" {
		logEvent = logEvent.Str("operation_details", operation)
	}
	if scope := event.Context[ContextKeyScope]; scope != "" {
		logEvent = logEvent.Str("scope", scope)
	}
	if err := event.Context[ContextKeyError]; err != "" {
		logEvent = logEvent.Str("error", err)
	}

	logEvent.Msg("Audit event")
	return nil
}

// GetEvents returns events matching the filter (not implemented for stdout logger)
func (l *StdoutAuditLogger) GetEvents(ctx context.Context, filter map[string]interface{}) ([]*AuditEvent, error) {
	return nil, fmt.Errorf("getting events not supported for stdout logger")
}

// WithContext creates a new context with audit information
func WithContext(ctx context.Context, collection, recordID, fieldName, fieldType string) context.Context {
	ctx = context.WithValue(ctx, contextKeyCollection, collection)
	ctx = context.WithValue(ctx, contextKeyRecordID, recordID)
	ctx = context.WithValue(ctx, contextKeyFieldName, fieldName)
	ctx = context.WithValue(ctx, contextKeyFieldType, fieldType)
	return ctx
}

// WithUserContext adds user-related information to the context
func WithUserContext(ctx context.Context, userID, orgID string) context.Context {
	ctx = context.WithValue(ctx, contextKeyUserID, userID)
	ctx = context.WithValue(ctx, contextKeyOrgID, orgID)
	return ctx
}

// WithDEKContext adds DEK-related information to the context
func WithDEKContext(ctx context.Context, dekID string) context.Context {
	return context.WithValue(ctx, contextKeyDEKID, dekID)
}

// WithEmailContext adds email information to the context
func WithEmailContext(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, contextKeyEmail, email)
}

// WithAuthEmail adds authenticated email information to the context
func WithAuthEmail(ctx context.Context, authEmail string) context.Context {
	return context.WithValue(ctx, contextKeyAuthEmail, authEmail)
}

// WithOperationContext adds operation details to the context
func WithOperationContext(ctx context.Context, details string) context.Context {
	return context.WithValue(ctx, contextKeyOperation, details)
}

// NewFieldOperation creates a new field operation context
func NewFieldOperation(collection, recordID, fieldName, fieldType string) *FieldOperation {
	return &FieldOperation{
		Collection: collection,
		RecordID:   recordID,
		FieldName:  fieldName,
		FieldType:  fieldType,
	}
}

// WithEmail adds email to the field operation
func (f *FieldOperation) WithEmail(email string) *FieldOperation {
	f.Email = email
	return f
}

// WithUser adds user information to the field operation
func (f *FieldOperation) WithUser(userID, orgID string) *FieldOperation {
	f.UserID = userID
	f.OrgID = orgID
	return f
}

// WithDEK adds DEK information to the field operation
func (f *FieldOperation) WithDEK(dekID string, version int) *FieldOperation {
	f.DEKID = dekID
	f.DEKVersion = version
	return f
}

// WithOperation adds operation details
func (f *FieldOperation) WithOperation(operation string) *FieldOperation {
	f.Operation = operation
	return f
}

// ToContext creates a context with all field operation information
func (f *FieldOperation) ToContext(ctx context.Context) context.Context {
	ctx = WithContext(ctx, f.Collection, f.RecordID, f.FieldName, f.FieldType)
	if f.Email != "" {
		ctx = WithEmailContext(ctx, f.Email)
	}
	if f.UserID != "" || f.OrgID != "" {
		ctx = WithUserContext(ctx, f.UserID, f.OrgID)
	}
	if f.DEKID != "" {
		ctx = WithDEKContext(ctx, f.DEKID)
	}
	if f.Operation != "" {
		ctx = WithOperationContext(ctx, f.Operation)
	}
	return ctx
}

// NewAuditEvent creates a new audit event with common fields
func NewAuditEvent(eventType, operation string, dekVersion int) *AuditEvent {
	return &AuditEvent{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC(),
		EventType:  eventType,
		Operation:  operation,
		Status:     StatusSuccess,
		DEKVersion: dekVersion,
		Context:    make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}
}

// AuditEventBuilder helps build audit events with proper context
type AuditEventBuilder struct {
	event *AuditEvent
}

// NewAuditEventBuilder creates a new builder for audit events
func NewAuditEventBuilder(eventType, operation string) *AuditEventBuilder {
	return &AuditEventBuilder{
		event: &AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			EventType: eventType,
			Operation: operation,
			Status:    StatusSuccess,
			Context:   make(map[string]string),
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithDEKVersion adds DEK version to the event
func (b *AuditEventBuilder) WithDEKVersion(version int) *AuditEventBuilder {
	b.event.DEKVersion = version
	return b
}

// WithStatus sets the event status
func (b *AuditEventBuilder) WithStatus(status string) *AuditEventBuilder {
	b.event.Status = status
	return b
}

// WithError adds error information to the event
func (b *AuditEventBuilder) WithError(err error) *AuditEventBuilder {
	if err != nil {
		b.event.Status = StatusFailed
		b.event.Context[ContextKeyError] = err.Error()
	}
	return b
}

// WithReason adds a reason to the event
func (b *AuditEventBuilder) WithReason(reason string) *AuditEventBuilder {
	b.event.Context["reason"] = reason
	return b
}

// WithScope adds scope information to the event
func (b *AuditEventBuilder) WithScope(scope, id string) *AuditEventBuilder {
	b.event.Context[ContextKeyScope] = scope
	b.event.Context["id"] = id
	b.event.Metadata["scope"] = scope
	b.event.Metadata["service_id"] = id
	return b
}

// FromContext extracts all relevant information from the context
func (b *AuditEventBuilder) FromContext(ctx context.Context) *AuditEventBuilder {
	// Extract all possible context values
	contextKeys := []struct {
		key      contextKey
		ctxKey   string
		metaKey  string
		required bool
	}{
		{contextKeyCollection, ContextKeyCollection, "collection", true},
		{contextKeyRecordID, ContextKeyRecordID, "record_id", true},
		{contextKeyFieldName, ContextKeyFieldName, "field_name", false},
		{contextKeyFieldType, ContextKeyFieldType, "field_type", false},
		{contextKeyUserID, ContextKeyUserID, "user_id", false},
		{contextKeyEmail, ContextKeyEmail, "email", false},
		{contextKeyAuthEmail, ContextKeyAuthEmail, "auth_email", false},
		{contextKeyOrgID, ContextKeyOrgID, "org_id", false},
		{contextKeyOperation, ContextKeyOperation, "operation", false},
	}

	// Extract and set values from context
	for _, k := range contextKeys {
		if value, ok := ctx.Value(k.key).(string); ok && value != "" {
			b.event.Context[k.ctxKey] = value
			b.event.Metadata[k.metaKey] = value
		} else if k.required {
			log.Warn().
				Str("missing_key", string(k.key)).
				Msg("Required context key missing in audit event")
		}
	}

	// Build field operation string if we have the required fields
	if collection := b.event.Context[ContextKeyCollection]; collection != "" {
		if fieldName := b.event.Context[ContextKeyFieldName]; fieldName != "" {
			if fieldType := b.event.Context[ContextKeyFieldType]; fieldType != "" {
				b.event.Metadata["field_operation"] = fmt.Sprintf("%s.%s (%s)",
					collection, fieldName, fieldType)
			}
		}
	}

	return b
}

// WithCustomContext adds custom context values
func (b *AuditEventBuilder) WithCustomContext(key string, value interface{}) *AuditEventBuilder {
	if strVal, ok := value.(string); ok {
		b.event.Context[key] = strVal
	}
	b.event.Metadata[key] = value
	return b
}

// Build creates the final audit event
func (b *AuditEventBuilder) Build() *AuditEvent {
	// Ensure required fields
	if b.event.Context[ContextKeyScope] == "" {
		b.event.Context[ContextKeyScope] = ContextKeySystem
	}
	return b.event
}
