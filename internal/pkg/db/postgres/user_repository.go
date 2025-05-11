package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/verigate/verigate-server/internal/app/user"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) user.Repository {
	return &userRepository{db: db}
}

func (r *userRepository) Save(ctx context.Context, user *user.User) error {
	query := `
		INSERT INTO users (username, email, password_hash, full_name, is_active, is_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.FullName,
		user.IsActive,
		user.IsVerified,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(&user.ID)

	if err != nil {
		return errors.Internal("Failed to create user")
	}

	return nil
}

func (r *userRepository) Update(ctx context.Context, user *user.User) error {
	query := `
		UPDATE users
		SET full_name = $2, profile_picture_url = $3, phone_number = $4, updated_at = $5
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.FullName,
		user.ProfilePictureURL,
		user.PhoneNumber,
		user.UpdatedAt,
	)

	if err != nil {
		return errors.Internal("Failed to update user")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("User not found")
	}

	return nil
}

func (r *userRepository) FindByID(ctx context.Context, id uint) (*user.User, error) {
	var u user.User
	query := `
		SELECT id, username, email, password_hash, full_name, profile_picture_url, phone_number,
		       is_active, is_verified, created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.FullName,
		&u.ProfilePictureURL,
		&u.PhoneNumber,
		&u.IsActive,
		&u.IsVerified,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.LastLoginAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal("Failed to get user")
	}

	return &u, nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	var u user.User
	query := `
		SELECT id, username, email, password_hash, full_name, profile_picture_url, phone_number,
		       is_active, is_verified, created_at, updated_at, last_login_at
		FROM users WHERE email = $1
	`

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.FullName,
		&u.ProfilePictureURL,
		&u.PhoneNumber,
		&u.IsActive,
		&u.IsVerified,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.LastLoginAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal("Failed to get user by email")
	}

	return &u, nil
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*user.User, error) {
	var u user.User
	query := `
		SELECT id, username, email, password_hash, full_name, profile_picture_url, phone_number,
		       is_active, is_verified, created_at, updated_at, last_login_at
		FROM users WHERE username = $1
	`

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.FullName,
		&u.ProfilePictureURL,
		&u.PhoneNumber,
		&u.IsActive,
		&u.IsVerified,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.LastLoginAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal("Failed to get user by username")
	}

	return &u, nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, id uint, passwordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $2, updated_at = $3
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id, passwordHash, time.Now())
	if err != nil {
		return errors.Internal("Failed to update password")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("User not found")
	}

	return nil
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, id uint) error {
	query := `
		UPDATE users
		SET last_login_at = $2
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, time.Now())
	if err != nil {
		return errors.Internal("Failed to update last login")
	}

	return nil
}

func (r *userRepository) Delete(ctx context.Context, id uint) error {
	query := "DELETE FROM users WHERE id = $1"

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.Internal("Failed to delete user")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("User not found")
	}

	return nil
}
