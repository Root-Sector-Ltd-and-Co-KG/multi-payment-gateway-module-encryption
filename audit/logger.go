// Package audit provides audit logging functionality for encryption operations
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/root-sector/multi-payment-gateway-module-encryption/types"
	"github.com/rs/zerolog/log"
)

// Core context keys for encryption operations
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
)

// StdoutAuditLogger implements Logger interface writing to stdout
type StdoutAuditLogger struct{}

// NewStdoutAuditLogger creates a new stdout audit logger
func NewStdoutAuditLogger() *StdoutAuditLogger {
	return &StdoutAuditLogger{}
}

// Printf implements the required Printf method from the interfaces.AuditLogger interface
func (l *StdoutAuditLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
}

// LogEvent logs an audit event to stdout with essential context information
func (l *StdoutAuditLogger) LogEvent(ctx context.Context, event *types.AuditEvent) error {
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

	// Create log event with core fields
	logEvent := log.Debug().
		Str("auditId", event.ID).
		Time("timestamp", event.Timestamp).
		Str("eventType", event.EventType).
		Str("operation", event.Operation).
		Str("status", event.Status).
		Int("dekVersion", event.DEKVersion)

	// Add essential context fields
	if scope := event.Context[string(KeyScope)]; scope != "" {
		logEvent = logEvent.Str("scope", scope)
	}
	if collection := event.Context[string(KeyCollection)]; collection != "" {
		logEvent = logEvent.Str("collection", collection)
	}
	if fieldName := event.Context[string(KeyFieldName)]; fieldName != "" {
		logEvent = logEvent.Str("fieldName", fieldName)
	}
	if dekID := event.Context[string(KeyDEKID)]; dekID != "" {
		logEvent = logEvent.Str("dekId", dekID)
	}
	if orgID := event.Context[string(KeyOrgID)]; orgID != "" {
		logEvent = logEvent.Str("orgId", orgID)
	}
	if err := event.Context[string(KeyError)]; err != "" {
		logEvent = logEvent.Str("error", err)
	}
	if userEmail := event.Context[string(KeyUserEmail)]; userEmail != "" {
		logEvent = logEvent.Str("userEmail", userEmail)
	}
	if userID := event.Context[string(KeyUserID)]; userID != "" {
		logEvent = logEvent.Str("userId", userID)
	}
	if operation := event.Context[string(KeyOperation)]; operation != "" {
		logEvent = logEvent.Str("operation", operation)
	}

	logEvent.Msg("Audit event")
	return nil
}

// GetEvents returns events matching the filter (not implemented for stdout logger)
func (l *StdoutAuditLogger) GetEvents(ctx context.Context, filter map[string]interface{}) ([]*types.AuditEvent, error) {
	return nil, fmt.Errorf("getting events not supported for stdout logger")
}

// WithContext creates a new context with essential audit information
func WithContext(ctx context.Context, scope, collection, fieldName string) context.Context {
	ctx = context.WithValue(ctx, KeyScope, scope)
	ctx = context.WithValue(ctx, KeyCollection, collection)
	ctx = context.WithValue(ctx, KeyFieldName, fieldName)
	return ctx
}

// WithOrganization adds organization ID to the context
func WithOrganization(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, KeyOrgID, orgID)
}

// WithDEK adds DEK ID to the context
func WithDEK(ctx context.Context, dekID string) context.Context {
	return context.WithValue(ctx, KeyDEKID, dekID)
}

// WithUserContext adds user information to the context
func WithUserContext(ctx context.Context, userID, userEmail string) context.Context {
	if userID != "" {
		ctx = context.WithValue(ctx, KeyUserID, userID)
	}
	if userEmail != "" {
		ctx = context.WithValue(ctx, KeyUserEmail, userEmail)
	}
	return ctx
}

// WithOperation adds operation information to the context
func WithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, KeyOperation, operation)
}

// WithFieldType adds field type information to the context
func WithFieldType(ctx context.Context, fieldType string) context.Context {
	return context.WithValue(ctx, KeyFieldType, fieldType)
}

// WithRecordID adds record ID information to the context
func WithRecordID(ctx context.Context, recordID string) context.Context {
	return context.WithValue(ctx, KeyRecordID, recordID)
}

// NewAuditEvent creates a new audit event with essential fields
func NewAuditEvent(eventType, operation string, dekVersion int) *types.AuditEvent {
	return &types.AuditEvent{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC(),
		EventType:  eventType,
		Operation:  operation,
		Status:     StatusSuccess,
		DEKVersion: dekVersion,
		Context:    make(map[string]string),
	}
}
