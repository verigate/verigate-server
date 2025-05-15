// Package token provides functionality for OAuth token management.
package token

import (
	"context"
)

// Repository defines the interface for token data storage and retrieval operations.
type Repository interface {
	// Access token methods

	// SaveAccessToken stores a new access token in the database
	SaveAccessToken(ctx context.Context, token *AccessToken) error

	// FindAccessToken retrieves an access token by its ID
	FindAccessToken(ctx context.Context, tokenID string) (*AccessToken, error)

	// FindAccessTokensByUserID retrieves a paginated list of access tokens for a specific user
	FindAccessTokensByUserID(ctx context.Context, userID uint, page, limit int) ([]AccessToken, int64, error)

	// FindAccessTokensByClientID retrieves a paginated list of access tokens for a specific client
	FindAccessTokensByClientID(ctx context.Context, clientID string, page, limit int) ([]AccessToken, int64, error)

	// RevokeAccessToken marks an access token as revoked
	RevokeAccessToken(ctx context.Context, tokenID string) error

	// RevokeAccessTokensByUserID revokes all access tokens for a specific user
	RevokeAccessTokensByUserID(ctx context.Context, userID uint) error

	// RevokeAccessTokensByClientID revokes all access tokens for a specific client
	RevokeAccessTokensByClientID(ctx context.Context, clientID string) error

	// RevokeAccessTokensByAuthCode revokes all access tokens associated with an authorization code
	RevokeAccessTokensByAuthCode(ctx context.Context, authCode string) error

	// IsAccessTokenRevoked checks if an access token has been revoked
	IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error)

	// Refresh token methods

	// SaveRefreshToken stores a new refresh token in the database
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error

	// FindRefreshToken retrieves a refresh token by its ID
	FindRefreshToken(ctx context.Context, tokenID string) (*RefreshToken, error)

	// FindRefreshTokenByHash retrieves a refresh token by its hash value
	FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)

	// FindRefreshTokensByUserID retrieves a paginated list of refresh tokens for a specific user
	FindRefreshTokensByUserID(ctx context.Context, userID uint, page, limit int) ([]RefreshToken, int64, error)

	// FindRefreshTokensByClientID retrieves a paginated list of refresh tokens for a specific client
	FindRefreshTokensByClientID(ctx context.Context, clientID string, page, limit int) ([]RefreshToken, int64, error)

	// RevokeRefreshToken marks a refresh token as revoked
	RevokeRefreshToken(ctx context.Context, tokenID string) error

	// RevokeRefreshTokensByUserID revokes all refresh tokens for a specific user
	RevokeRefreshTokensByUserID(ctx context.Context, userID uint) error

	// RevokeRefreshTokensByClientID revokes all refresh tokens for a specific client
	RevokeRefreshTokensByClientID(ctx context.Context, clientID string) error

	// RevokeRefreshTokensByAccessTokenID revokes all refresh tokens for a specific access token
	RevokeRefreshTokensByAccessTokenID(ctx context.Context, accessTokenID string) error
}
