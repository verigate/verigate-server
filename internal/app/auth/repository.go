package auth

import (
	"context"
)

// Repository interface for authentication-related data storage and retrieval.
type Repository interface {
	// SaveRefreshToken stores a new refresh token.
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error

	// FindRefreshToken looks up a refresh token by ID.
	FindRefreshToken(ctx context.Context, tokenID string) (*RefreshToken, error)

	// FindRefreshTokenByToken finds a refresh token by its hashed token value.
	FindRefreshTokenByToken(ctx context.Context, hashedToken string) (*RefreshToken, error)

	// RevokeRefreshToken marks a specific token as revoked.
	RevokeRefreshToken(ctx context.Context, tokenID string) error

	// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
	RevokeAllUserRefreshTokens(ctx context.Context, userID uint) error

	// DeleteExpiredTokens removes expired tokens.
	DeleteExpiredTokens(ctx context.Context) error

	// IsRefreshTokenRevoked checks if a refresh token has been revoked.
	IsRefreshTokenRevoked(ctx context.Context, tokenID string) (bool, error)
}
