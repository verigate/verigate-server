package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/verigate/verigate-server/internal/app/oauth"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

type oauthRepository struct {
	db *sql.DB
}

func NewOAuthRepository(db *sql.DB) oauth.Repository {
	return &oauthRepository{db: db}
}

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
		return errors.Internal("Failed to save authorization code")
	}

	return nil
}

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
		return nil, errors.Internal("Failed to find authorization code")
	}

	return &ac, nil
}

func (r *oauthRepository) MarkCodeAsUsed(ctx context.Context, code string) error {
	query := `
		UPDATE authorization_codes
		SET is_used = true
		WHERE code = $1
	`

	result, err := r.db.ExecContext(ctx, query, code)
	if err != nil {
		return errors.Internal("Failed to mark code as used")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("Authorization code not found")
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
		return errors.Internal("Failed to delete expired codes")
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
		return errors.Internal("Failed to save user consent")
	}

	return nil
}

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
		return nil, errors.Internal("Failed to find user consent")
	}

	return &uc, nil
}

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
		return errors.Internal("Failed to update user consent")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("User consent not found")
	}

	return nil
}

func (r *oauthRepository) DeleteUserConsent(ctx context.Context, userID uint, clientID string) error {
	query := `
		DELETE FROM user_consents
		WHERE user_id = $1 AND client_id = $2
	`

	result, err := r.db.ExecContext(ctx, query, userID, clientID)
	if err != nil {
		return errors.Internal("Failed to delete user consent")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("User consent not found")
	}

	return nil
}
