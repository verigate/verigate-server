// Package oauth provides functionality for implementing OAuth 2.0 authorization flows,
// including authorization code, implicit, password, and client credentials.
package oauth

import (
	"context"
)

// Repository defines the interface for OAuth data storage and retrieval operations.
// It handles authorization codes and user consent records.
type Repository interface {
	// Authorization code methods

	// SaveAuthorizationCode persists a new authorization code
	SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

	// FindAuthorizationCode retrieves an authorization code by its value
	FindAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// MarkCodeAsUsed updates an authorization code to indicate it has been exchanged for tokens
	MarkCodeAsUsed(ctx context.Context, code string) error

	// DeleteExpiredCodes removes expired authorization codes from storage
	DeleteExpiredCodes(ctx context.Context) error

	// User consent methods

	// SaveUserConsent stores a user's consent for client access to specific scopes
	SaveUserConsent(ctx context.Context, consent *UserConsent) error

	// FindUserConsent retrieves a user's consent record for a specific client
	FindUserConsent(ctx context.Context, userID uint, clientID string) (*UserConsent, error)

	// UpdateUserConsent updates an existing user consent record, typically for scope changes
	UpdateUserConsent(ctx context.Context, consent *UserConsent) error

	// DeleteUserConsent removes a user's consent for a specific client
	DeleteUserConsent(ctx context.Context, userID uint, clientID string) error
}
