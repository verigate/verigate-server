// Package postgres provides PostgreSQL implementations of the application's repositories.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/verigate/verigate-server/internal/app/oauth"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

// oauthRepository implements the oauth.Repository interface using PostgreSQL.
type oauthRepository struct {
	db *sql.DB
}

// NewOAuthRepository creates a new PostgreSQL-based OAuth repository.
// It takes a database connection and returns an oauth.Repository interface.
func NewOAuthRepository(db *sql.DB) oauth.Repository {
	return &oauthRepository{db: db}
}

// SaveAuthorizationCode persists a new OAuth authorization code in the PostgreSQL database.
// It inserts all code fields and returns the generated ID.
// This is used during the authorization code OAuth flow.
func (r *oauthRepository) SaveAuthorizationCode(ctx context.Context, code *oauth.AuthorizationCode) error {
	query := `
		INSERT INTO authorization_codes (
			code, client_id, user_id, redirect_uri, scope,
			code_challenge, code_challenge_method, expires_at, created_at, is_used
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		code.Code,
		code.ClientID,
		code.UserID,
		code.RedirectURI,
		code.Scope,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.ExpiresAt,
		code.CreatedAt,
		code.IsUsed,
	).Scan(&code.ID)

	if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToSaveAuthCode, err.Error()))
	}

	return nil
}

// FindAuthorizationCode retrieves an authorization code from the database by its value.
// Returns the code object if found, nil if the code doesn't exist,
// or an error if the query fails.
// This is used during the token exchange step of the OAuth flow.
func (r *oauthRepository) FindAuthorizationCode(ctx context.Context, code string) (*oauth.AuthorizationCode, error) {
	var ac oauth.AuthorizationCode
	query := `
		SELECT id, code, client_id, user_id, redirect_uri, scope,
		       code_challenge, code_challenge_method, expires_at, created_at, is_used
		FROM authorization_codes
		WHERE code = $1
	`

	err := r.db.QueryRowContext(ctx, query, code).Scan(
		&ac.ID,
		&ac.Code,
		&ac.ClientID,
		&ac.UserID,
		&ac.RedirectURI,
		&ac.Scope,
		&ac.CodeChallenge,
		&ac.CodeChallengeMethod,
		&ac.ExpiresAt,
		&ac.CreatedAt,
		&ac.IsUsed,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToFindAuthCode, err.Error()))
	}

	return &ac, nil
}

// MarkCodeAsUsed updates an authorization code to mark it as used.
// Authorization codes are one-time use only, and this method is called
// after a code has been successfully exchanged for a token.
// Returns an error if the update fails.
func (r *oauthRepository) MarkCodeAsUsed(ctx context.Context, code string) error {
	query := `
		UPDATE authorization_codes
		SET is_used = true
		WHERE code = $1
	`

	result, err := r.db.ExecContext(ctx, query, code)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToMarkCodeAsUsed)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToGetAffectedRows, err.Error()))
	}

	if rows == 0 {
		return errors.NotFound(errors.ErrMsgAuthorizationCodeNotFound)
	}

	return nil
}

func (r *oauthRepository) DeleteExpiredCodes(ctx context.Context) error {
	query := `
		DELETE FROM authorization_codes
		WHERE expires_at < $1
	`

	_, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToDeleteExpiredCodes)
	}

	return nil
}

func (r *oauthRepository) SaveUserConsent(ctx context.Context, consent *oauth.UserConsent) error {
	query := `
		INSERT INTO user_consents (user_id, client_id, scope, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		consent.UserID,
		consent.ClientID,
		consent.Scope,
		consent.CreatedAt,
		consent.UpdatedAt,
	).Scan(&consent.ID)

	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToSaveUserConsent)
	}

	return nil
}

// FindUserConsent retrieves a user's consent record for a specific client.
// User consents store the permissions (scopes) that a user has granted to a client application.
// Returns the consent if found, nil if no consent exists, or an error if the query fails.
func (r *oauthRepository) FindUserConsent(ctx context.Context, userID uint, clientID string) (*oauth.UserConsent, error) {
	var uc oauth.UserConsent
	query := `
		SELECT id, user_id, client_id, scope, created_at, updated_at
		FROM user_consents
		WHERE user_id = $1 AND client_id = $2
	`

	err := r.db.QueryRowContext(ctx, query, userID, clientID).Scan(
		&uc.ID,
		&uc.UserID,
		&uc.ClientID,
		&uc.Scope,
		&uc.CreatedAt,
		&uc.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToFindUserConsent, err.Error()))
	}

	return &uc, nil
}

// UpdateUserConsent modifies an existing user consent record.
// This is typically called when a user grants additional permissions to a client.
// Returns NotFound error if no consent exists, or Internal error if the update fails.
func (r *oauthRepository) UpdateUserConsent(ctx context.Context, consent *oauth.UserConsent) error {
	query := `
		UPDATE user_consents
		SET scope = $3, updated_at = $4
		WHERE user_id = $1 AND client_id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		consent.UserID,
		consent.ClientID,
		consent.Scope,
		consent.UpdatedAt,
	)

	if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToUpdateUserConsent, err.Error()))
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToGetAffectedRows, err.Error()))
	}

	if rows == 0 {
		return errors.NotFound(fmt.Sprintf(errors.ErrMsgUserConsentNotFoundForUserAndClient, consent.UserID, consent.ClientID))
	}

	return nil
}

// DeleteUserConsent removes a user's consent for a specific client.
// This is typically called when a user revokes permissions from a client application.
// Returns NotFound error if no consent exists, or Internal error if the deletion fails.
func (r *oauthRepository) DeleteUserConsent(ctx context.Context, userID uint, clientID string) error {
	query := `
		DELETE FROM user_consents
		WHERE user_id = $1 AND client_id = $2
	`

	result, err := r.db.ExecContext(ctx, query, userID, clientID)
	if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToDeleteUserConsent, err.Error()))
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal(fmt.Sprintf("%s: %s", errors.ErrMsgFailedToGetAffectedRows, err.Error()))
	}

	if rows == 0 {
		return errors.NotFound(fmt.Sprintf(errors.ErrMsgUserConsentNotFoundForUserAndClient, userID, clientID))
	}

	return nil
}
