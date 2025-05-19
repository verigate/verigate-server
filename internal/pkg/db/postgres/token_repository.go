// Package postgres provides PostgreSQL database connection and repository implementations
// for the Verigate Server application.
package postgres

import (
	"context"
	"database/sql"

	"github.com/verigate/verigate-server/internal/app/token"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

// tokenRepository implements the token.Repository interface using PostgreSQL.
// It handles persistence of OAuth access and refresh tokens.
type tokenRepository struct {
	db *sql.DB
}

// NewTokenRepository creates a new PostgreSQL implementation of the token repository.
// It requires an active database connection to operate.
func NewTokenRepository(db *sql.DB) token.Repository {
	return &tokenRepository{db: db}
}

// SaveAccessToken persists a new access token to the database.
// It stores all token properties and sets the auto-generated ID in the token object.
// Returns an error if the database operation fails.
func (r *tokenRepository) SaveAccessToken(ctx context.Context, token *token.AccessToken) error {
	query := `
		INSERT INTO access_tokens (token_id, token_hash, client_id, user_id, scope, expires_at, created_at, is_revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		token.TokenID,
		token.TokenHash,
		token.ClientID,
		token.UserID,
		token.Scope,
		token.ExpiresAt,
		token.CreatedAt,
		token.IsRevoked,
	).Scan(&token.ID)

	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToSaveAccessToken)
	}

	return nil
}

// FindAccessToken retrieves an access token from the database by its token ID.
// Returns the token or an error if not found or if the database operation fails.
func (r *tokenRepository) FindAccessToken(ctx context.Context, tokenID string) (*token.AccessToken, error) {
	var t token.AccessToken
	query := `
		SELECT id, token_id, token_hash, client_id, user_id, scope, expires_at, created_at, is_revoked
		FROM access_tokens
		WHERE token_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(
		&t.ID,
		&t.TokenID,
		&t.TokenHash,
		&t.ClientID,
		&t.UserID,
		&t.Scope,
		&t.ExpiresAt,
		&t.CreatedAt,
		&t.IsRevoked,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToFindAccessToken)
	}

	return &t, nil
}

func (r *tokenRepository) FindAccessTokensByUserID(ctx context.Context, userID uint, page, limit int) ([]token.AccessToken, int64, error) {
	offset := (page - 1) * limit

	// Get total count
	var total int64
	countQuery := "SELECT COUNT(*) FROM access_tokens WHERE user_id = $1"
	if err := r.db.QueryRowContext(ctx, countQuery, userID).Scan(&total); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToCountAccessTokens)
	}

	// Get tokens with pagination
	query := `
		SELECT id, token_id, token_hash, client_id, user_id, scope, expires_at, created_at, is_revoked
		FROM access_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToGetAccessTokens)
	}
	defer rows.Close()

	var tokens []token.AccessToken
	for rows.Next() {
		var t token.AccessToken
		if err := rows.Scan(
			&t.ID,
			&t.TokenID,
			&t.TokenHash,
			&t.ClientID,
			&t.UserID,
			&t.Scope,
			&t.ExpiresAt,
			&t.CreatedAt,
			&t.IsRevoked,
		); err != nil {
			return nil, 0, errors.Internal(errors.ErrMsgFailedToScanAccessToken)
		}
		tokens = append(tokens, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgErrorIteratingAccessTokens)
	}

	return tokens, total, nil
}

func (r *tokenRepository) FindAccessTokensByClientID(ctx context.Context, clientID string, page, limit int) ([]token.AccessToken, int64, error) {
	offset := (page - 1) * limit

	// Get total count
	var total int64
	countQuery := "SELECT COUNT(*) FROM access_tokens WHERE client_id = $1"
	if err := r.db.QueryRowContext(ctx, countQuery, clientID).Scan(&total); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToCountAccessTokens)
	}

	// Get tokens with pagination
	query := `
		SELECT id, token_id, token_hash, client_id, user_id, scope, expires_at, created_at, is_revoked
		FROM access_tokens
		WHERE client_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, clientID, limit, offset)
	if err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToGetAccessTokens)
	}
	defer rows.Close()

	var tokens []token.AccessToken
	for rows.Next() {
		var t token.AccessToken
		if err := rows.Scan(
			&t.ID,
			&t.TokenID,
			&t.TokenHash,
			&t.ClientID,
			&t.UserID,
			&t.Scope,
			&t.ExpiresAt,
			&t.CreatedAt,
			&t.IsRevoked,
		); err != nil {
			return nil, 0, errors.Internal(errors.ErrMsgFailedToScanAccessToken)
		}
		tokens = append(tokens, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgErrorIteratingAccessTokens)
	}

	return tokens, total, nil
}

func (r *tokenRepository) RevokeAccessToken(ctx context.Context, tokenID string) error {
	query := `
		UPDATE access_tokens
		SET is_revoked = true
		WHERE token_id = $1
	`

	result, err := r.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeAccessToken)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToGetAffectedRows)
	}

	if rows == 0 {
		return errors.NotFound(errors.ErrMsgAccessTokenNotFound)
	}

	return nil
}

func (r *tokenRepository) RevokeAccessTokensByUserID(ctx context.Context, userID uint) error {
	query := `
		UPDATE access_tokens
		SET is_revoked = true
		WHERE user_id = $1 AND is_revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeAccessTokens)
	}

	return nil
}

func (r *tokenRepository) RevokeAccessTokensByClientID(ctx context.Context, clientID string) error {
	query := `
		UPDATE access_tokens
		SET is_revoked = true
		WHERE client_id = $1 AND is_revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, clientID)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeAccessTokens)
	}

	return nil
}

func (r *tokenRepository) RevokeAccessTokensByAuthCode(ctx context.Context, authCode string) error {
	// This would typically involve a join with authorization_codes table
	// For simplicity, we'll assume we track this relationship differently
	query := `
		UPDATE access_tokens
		SET is_revoked = true
		WHERE token_id IN (
			SELECT token_id FROM authorization_code_tokens WHERE auth_code = $1
		)
	`

	_, err := r.db.ExecContext(ctx, query, authCode)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeAccessTokensByAuthCode)
	}

	return nil
}

func (r *tokenRepository) IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	var isRevoked bool
	query := "SELECT is_revoked FROM access_tokens WHERE token_id = $1"

	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(&isRevoked)
	if err == sql.ErrNoRows {
		return true, nil // If token doesn't exist, consider it revoked
	}
	if err != nil {
		return false, errors.Internal(errors.ErrMsgFailedToCheckTokenRevocationStatus)
	}

	return isRevoked, nil
}

func (r *tokenRepository) SaveRefreshToken(ctx context.Context, token *token.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (token_id, token_hash, access_token_id, client_id, user_id, scope, expires_at, created_at, is_revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		token.TokenID,
		token.TokenHash,
		token.AccessTokenID,
		token.ClientID,
		token.UserID,
		token.Scope,
		token.ExpiresAt,
		token.CreatedAt,
		token.IsRevoked,
	).Scan(&token.ID)

	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToSaveRefreshToken)
	}

	return nil
}

func (r *tokenRepository) FindRefreshToken(ctx context.Context, tokenID string) (*token.RefreshToken, error) {
	var t token.RefreshToken
	query := `
		SELECT id, token_id, token_hash, access_token_id, client_id, user_id, scope, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE token_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(
		&t.ID,
		&t.TokenID,
		&t.TokenHash,
		&t.AccessTokenID,
		&t.ClientID,
		&t.UserID,
		&t.Scope,
		&t.ExpiresAt,
		&t.CreatedAt,
		&t.IsRevoked,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToFindRefreshToken)
	}

	return &t, nil
}

func (r *tokenRepository) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	var t token.RefreshToken
	query := `
		SELECT id, token_id, token_hash, access_token_id, client_id, user_id, scope, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&t.ID,
		&t.TokenID,
		&t.TokenHash,
		&t.AccessTokenID,
		&t.ClientID,
		&t.UserID,
		&t.Scope,
		&t.ExpiresAt,
		&t.CreatedAt,
		&t.IsRevoked,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToFindRefreshTokenByHash)
	}

	return &t, nil
}

func (r *tokenRepository) FindRefreshTokensByUserID(ctx context.Context, userID uint, page, limit int) ([]token.RefreshToken, int64, error) {
	offset := (page - 1) * limit

	// Get total count
	var total int64
	countQuery := "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1"
	if err := r.db.QueryRowContext(ctx, countQuery, userID).Scan(&total); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToCountRefreshTokens)
	}

	// Get tokens with pagination
	query := `
		SELECT id, token_id, token_hash, access_token_id, client_id, user_id, scope, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToGetRefreshTokens)
	}
	defer rows.Close()

	var tokens []token.RefreshToken
	for rows.Next() {
		var t token.RefreshToken
		if err := rows.Scan(
			&t.ID,
			&t.TokenID,
			&t.TokenHash,
			&t.AccessTokenID,
			&t.ClientID,
			&t.UserID,
			&t.Scope,
			&t.ExpiresAt,
			&t.CreatedAt,
			&t.IsRevoked,
		); err != nil {
			return nil, 0, errors.Internal(errors.ErrMsgFailedToScanRefreshToken)
		}
		tokens = append(tokens, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgErrorIteratingRefreshTokens)
	}

	return tokens, total, nil
}

func (r *tokenRepository) FindRefreshTokensByClientID(ctx context.Context, clientID string, page, limit int) ([]token.RefreshToken, int64, error) {
	offset := (page - 1) * limit

	// Get total count
	var total int64
	countQuery := "SELECT COUNT(*) FROM refresh_tokens WHERE client_id = $1"
	if err := r.db.QueryRowContext(ctx, countQuery, clientID).Scan(&total); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToCountRefreshTokens)
	}

	// Get tokens with pagination
	query := `
		SELECT id, token_id, token_hash, access_token_id, client_id, user_id, scope, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE client_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, clientID, limit, offset)
	if err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgFailedToGetRefreshTokens)
	}
	defer rows.Close()

	var tokens []token.RefreshToken
	for rows.Next() {
		var t token.RefreshToken
		if err := rows.Scan(
			&t.ID,
			&t.TokenID,
			&t.TokenHash,
			&t.AccessTokenID,
			&t.ClientID,
			&t.UserID,
			&t.Scope,
			&t.ExpiresAt,
			&t.CreatedAt,
			&t.IsRevoked,
		); err != nil {
			return nil, 0, errors.Internal(errors.ErrMsgFailedToScanRefreshToken)
		}
		tokens = append(tokens, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Internal(errors.ErrMsgErrorIteratingRefreshTokens)
	}

	return tokens, total, nil
}

func (r *tokenRepository) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true
		WHERE token_id = $1
	`

	result, err := r.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeRefreshToken)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToGetAffectedRows)
	}

	if rows == 0 {
		return errors.NotFound(errors.ErrMsgRefreshTokenNotFound)
	}

	return nil
}

func (r *tokenRepository) RevokeRefreshTokensByUserID(ctx context.Context, userID uint) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true
		WHERE user_id = $1 AND is_revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeRefreshTokens)
	}

	return nil
}

func (r *tokenRepository) RevokeRefreshTokensByClientID(ctx context.Context, clientID string) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true
		WHERE client_id = $1 AND is_revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, clientID)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeRefreshTokens)
	}

	return nil
}

func (r *tokenRepository) RevokeRefreshTokensByAccessTokenID(ctx context.Context, accessTokenID string) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true
		WHERE access_token_id = $1 AND is_revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, accessTokenID)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToRevokeRefreshTokens)
	}

	return nil
}
