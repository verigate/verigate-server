package token

import (
	"context"
)

type Repository interface {
	// Access token methods
	SaveAccessToken(ctx context.Context, token *AccessToken) error
	FindAccessToken(ctx context.Context, tokenID string) (*AccessToken, error)
	FindAccessTokensByUserID(ctx context.Context, userID uint, page, limit int) ([]AccessToken, int64, error)
	FindAccessTokensByClientID(ctx context.Context, clientID string, page, limit int) ([]AccessToken, int64, error)
	RevokeAccessToken(ctx context.Context, tokenID string) error
	RevokeAccessTokensByUserID(ctx context.Context, userID uint) error
	RevokeAccessTokensByClientID(ctx context.Context, clientID string) error
	RevokeAccessTokensByAuthCode(ctx context.Context, authCode string) error
	IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error)

	// Refresh token methods
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	FindRefreshToken(ctx context.Context, tokenID string) (*RefreshToken, error)
	FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	FindRefreshTokensByUserID(ctx context.Context, userID uint, page, limit int) ([]RefreshToken, int64, error)
	FindRefreshTokensByClientID(ctx context.Context, clientID string, page, limit int) ([]RefreshToken, int64, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeRefreshTokensByUserID(ctx context.Context, userID uint) error
	RevokeRefreshTokensByClientID(ctx context.Context, clientID string) error
	RevokeRefreshTokensByAccessTokenID(ctx context.Context, accessTokenID string) error
}
