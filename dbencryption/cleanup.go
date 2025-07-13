package dbencryption

import (
	"context"
	"fmt"
	"reflect"

	"github.com/rs/zerolog/log"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

// ValidateAndCleanPlaintextFields recursively walks through a struct and validates/cleans
// any field.Encrypted fields it finds. It validates that each encrypted field's ciphertext
// decrypts to its plaintext value, then removes the plaintext.
func ValidateAndCleanPlaintextFields(ctx context.Context, svc interfaces.FieldService, v interface{}) error {
	if v == nil {
		return nil
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("input must be a struct or pointer to struct")
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		// Handle types.Encrypted fields
		if field.Type() == reflect.TypeOf(types.FieldEncrypted{}) {
			encField := field.Addr().Interface().(*types.FieldEncrypted)

			if err := ValidateAndCleanPlaintext(ctx, svc, encField); err != nil {
				log.Warn().
					Err(err).
					Str("field", fieldType.Name).
					Msg("Failed to validate and clean encrypted field")
				continue
			}
			continue
		}

		// Recursively process struct fields
		switch field.Kind() {
		case reflect.Struct:
			if err := ValidateAndCleanPlaintextFields(ctx, svc, field.Addr().Interface()); err != nil {
				return fmt.Errorf("failed to process struct field %s: %w", fieldType.Name, err)
			}
		case reflect.Slice:
			for j := 0; j < field.Len(); j++ {
				item := field.Index(j)
				if item.Kind() == reflect.Struct {
					if err := ValidateAndCleanPlaintextFields(ctx, svc, item.Addr().Interface()); err != nil {
						return fmt.Errorf("failed to process slice item at index %d: %w", j, err)
					}
				}
			}
		case reflect.Map:
			iter := field.MapRange()
			for iter.Next() {
				val := iter.Value()
				if val.Kind() == reflect.Struct {
					if err := ValidateAndCleanPlaintextFields(ctx, svc, val.Addr().Interface()); err != nil {
						return fmt.Errorf("failed to process map value for key %v: %w", iter.Key().Interface(), err)
					}
				}
			}
		}
	}

	return nil
}

func ValidateAndCleanPlaintext(ctx context.Context, svc interfaces.FieldService, e *types.FieldEncrypted) error {
	if e == nil {
		return fmt.Errorf("encrypted field is nil")
	}

	// If there's no ciphertext, nothing to validate
	if e.Ciphertext == "" {
		return fmt.Errorf("no ciphertext to validate")
	}

	// Store original plaintext for validation
	originalPlaintext := e.Plaintext

	// Try to decrypt the field
	if err := svc.Decrypt(ctx, e); err != nil {
		// Restore original plaintext since decryption failed
		e.Plaintext = originalPlaintext
		return fmt.Errorf("failed to decrypt field for validation: %w", err)
	}

	// Validate decrypted value matches original plaintext
	if e.Plaintext != originalPlaintext {
		// Restore original plaintext since validation failed
		e.Plaintext = originalPlaintext
		return fmt.Errorf("decrypted value does not match original plaintext")
	}

	// Clear plaintext after successful validation
	e.Plaintext = ""
	return nil
}
