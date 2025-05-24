// Package auth provides authentication and authorization services
// for the application, including token generation, validation,
// and management of authentication sessions.
package auth

import (
	"context"
)

// Repository defines the interface for authentication-related data storage and retrieval.
// It handles persistence operations for refresh tokens and authorization sessions.
type Repository interface {
	// SaveRefreshToken stores a new refresh token.
	// The token is already hashed before being passed to this function.
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error

	// FindRefreshToken looks up a refresh token by ID.
	// Returns nil if the token doesn't exist.
	FindRefreshToken(ctx context.Context, tokenID string) (*RefreshToken, error)

	// FindRefreshTokenByToken finds a refresh token by its plain text token value.
	// It scans all tokens and compares the input with stored hashed values.
	// This is used during token refresh operations.
	// Returns nil if the token doesn't exist.
	FindRefreshTokenByToken(ctx context.Context, plainTextToken string) (*RefreshToken, error)

	// RevokeRefreshToken marks a specific token as revoked.
	// It should return an error if the token doesn't exist.
	RevokeRefreshToken(ctx context.Context, tokenID string) error

	// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
	// This is typically used during logout or password change operations.
	RevokeAllUserRefreshTokens(ctx context.Context, userID uint) error

	// DeleteExpiredTokens removes expired tokens.
	// This is a maintenance operation that should be performed periodically.
	DeleteExpiredTokens(ctx context.Context) error

	// IsRefreshTokenRevoked checks if a refresh token has been revoked.
	// Returns true if the token is revoked or doesn't exist.
	IsRefreshTokenRevoked(ctx context.Context, tokenID string) (bool, error)
}
