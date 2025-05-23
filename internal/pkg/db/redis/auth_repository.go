// Package redis provides Redis-based implementations of the application's repositories.
// It handles caching, authentication token storage, and other data that benefits from
// in-memory storage with persistence.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/verigate/verigate-server/internal/app/auth"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/hash"
)

// Constants for Redis key prefixes to avoid collisions and organize data
const (
	refreshTokenKeyPrefix = "auth:refresh_token:" // Prefix for individual token storage
	userTokensKeyPrefix   = "auth:user_tokens:"   // Prefix for user's token collection
)

// authRepository implements the auth.Repository interface using Redis for storage.
type authRepository struct {
	client *redis.Client
}

// NewAuthRepository creates a Redis-based authentication repository.
// It implements the auth.Repository interface for refresh token management.
func NewAuthRepository(client *redis.Client) auth.Repository {
	return &authRepository{client: client}
}

// SaveRefreshToken stores a new refresh token in Redis.
// It creates two entries:
// 1. The token itself with the token ID as key
// 2. An entry in the user's token set to track all tokens for a user
func (r *authRepository) SaveRefreshToken(ctx context.Context, token *auth.RefreshToken) error {
	// Serialize the refresh token data to JSON
	tokenData, err := json.Marshal(token)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToMarshalRefreshToken)
	}

	// Create a pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Store token by token ID
	tokenKey := refreshTokenKeyPrefix + token.ID
	pipe.Set(ctx, tokenKey, tokenData, time.Until(token.ExpiresAt))

	// Add to user's token list
	userTokensKey := userTokensKeyPrefix + fmt.Sprintf("%d", token.UserID)
	pipe.SAdd(ctx, userTokensKey, token.ID)
	pipe.ExpireAt(ctx, userTokensKey, token.ExpiresAt)

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToSaveRefreshToken, err.Error()))
	}

	return nil
}

// FindRefreshToken looks up a refresh token by ID.
// Returns nil if the token doesn't exist.
func (r *authRepository) FindRefreshToken(ctx context.Context, tokenID string) (*auth.RefreshToken, error) {
	tokenKey := refreshTokenKeyPrefix + tokenID
	data, err := r.client.Get(ctx, tokenKey).Result()

	if err == redis.Nil {
		return nil, nil // Token doesn't exist
	} else if err != nil {
		return nil, errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToFindRefreshToken, err.Error()))
	}

	var token auth.RefreshToken
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToUnmarshalRefreshToken)
	}

	return &token, nil
}

// FindRefreshTokenByToken looks up a refresh token by its plain text token value.
// This is a more expensive operation as it requires scanning all tokens and comparing hashes.
// Returns nil if the token doesn't exist.
func (r *authRepository) FindRefreshTokenByToken(ctx context.Context, plainTextToken string) (*auth.RefreshToken, error) {
	// Scan all token keys
	var cursor uint64
	var keys []string
	var err error

	for {
		keys, cursor, err = r.client.Scan(ctx, cursor, refreshTokenKeyPrefix+"*", 100).Result()
		if err != nil {
			return nil, errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToScanRefreshToken, err.Error()))
		}

		// Check each token
		for _, key := range keys {
			data, err := r.client.Get(ctx, key).Result()
			if err != nil {
				continue // Skip this token
			}

			var token auth.RefreshToken
			if err := json.Unmarshal([]byte(data), &token); err != nil {
				continue // Skip this token
			}

			// Verify the token using hash compare
			if hash.CompareHashAndPassword(token.Token, plainTextToken) == nil {
				return &token, nil
			}
		}

		if cursor == 0 {
			break
		}
	}

	return nil, nil // No matching token found
}

// RevokeRefreshToken marks a specific refresh token as revoked.
func (r *authRepository) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	tokenKey := refreshTokenKeyPrefix + tokenID

	// Get the existing token
	data, err := r.client.Get(ctx, tokenKey).Result()
	if err == redis.Nil {
		return errors.NotFound(errors.ErrMsgRefreshTokenNotFound)
	} else if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToGetRefreshToken, err.Error()))
	}

	var token auth.RefreshToken
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return errors.Internal(errors.ErrMsgFailedToUnmarshalRefreshToken)
	}

	// Mark the token as revoked
	token.IsRevoked = true

	// Save the updated token
	updatedData, err := json.Marshal(token)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToMarshalUpdatedRefreshToken)
	}

	// Preserve the expiry time
	ttl, err := r.client.TTL(ctx, tokenKey).Result()
	if err != nil {
		ttl = time.Until(token.ExpiresAt) // Use default if TTL fails
	}

	return r.client.Set(ctx, tokenKey, updatedData, ttl).Err()
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
func (r *authRepository) RevokeAllUserRefreshTokens(ctx context.Context, userID uint) error {
	userTokensKey := userTokensKeyPrefix + fmt.Sprintf("%d", userID)

	// Get all token IDs for the user
	tokenIDs, err := r.client.SMembers(ctx, userTokensKey).Result()
	if err != nil && err != redis.Nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToGetRefreshTokens, err.Error()))
	}

	// Revoke each token
	for _, tokenID := range tokenIDs {
		if err := r.RevokeRefreshToken(ctx, tokenID); err != nil {
			// Log error but continue with the others
			// TODO: Add proper logging
		}
	}

	return nil
}

// DeleteExpiredTokens removes expired tokens.
// Redis automatically removes expired keys, so this is a no-op.
func (r *authRepository) DeleteExpiredTokens(ctx context.Context) error {
	// Redis handles key expiration automatically
	return nil
}

// IsRefreshTokenRevoked checks if a refresh token has been revoked.
func (r *authRepository) IsRefreshTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	token, err := r.FindRefreshToken(ctx, tokenID)
	if err != nil {
		return false, err
	}

	if token == nil {
		return true, nil // Token not found, consider revoked
	}

	return token.IsRevoked, nil
}
