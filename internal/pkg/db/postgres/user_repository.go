// Package postgres provides PostgreSQL implementations of the application's repositories.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/verigate/verigate-server/internal/app/user"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

// userRepository implements the user.Repository interface using PostgreSQL.
type userRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new PostgreSQL-based user repository.
// It takes a database connection and returns a user.Repository interface.
func NewUserRepository(db *sql.DB) user.Repository {
	return &userRepository{db: db}
}

// Save creates a new user in the PostgreSQL database.
// It inserts all user fields and returns the generated ID.
// Returns an error if the insertion fails, for example due to a duplicate username or email.
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
		// Check if it's a unique constraint violation on username or email
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			if pqErr.Constraint == "users_username_key" {
				return errors.Conflict("Username already exists")
			} else if pqErr.Constraint == "users_email_key" {
				return errors.Conflict("Email already exists")
			}
		}
		return errors.Internal("Failed to create user: " + err.Error())
	}

	return nil
}

// Update modifies an existing user's profile information in the PostgreSQL database.
// It updates mutable profile fields like full name, profile picture, and phone number.
// Returns NotFound error if the user doesn't exist, or Internal error if the update fails.
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
		return errors.Internal("Failed to update user: " + err.Error())
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows: " + err.Error())
	}

	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("User with ID %d not found", user.ID))
	}

	return nil
}

// FindByID retrieves a user from the PostgreSQL database by their internal ID.
// Returns the user if found, nil if the user doesn't exist, or an error if the query fails.
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
		return nil, errors.Internal("Failed to get user by ID: " + err.Error())
	}

	return &u, nil
}

// FindByEmail retrieves a user from the PostgreSQL database by their email address.
// Returns the user if found, nil if the user doesn't exist, or an error if the query fails.
// This method is case-insensitive for email addresses.
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
		return nil, errors.Internal("Failed to get user by email: " + err.Error())
	}

	return &u, nil
}

// FindByUsername retrieves a user from the PostgreSQL database by their username.
// Returns the user if found, nil if the user doesn't exist, or an error if the query fails.
// This method is case-sensitive for usernames.
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
		return nil, errors.Internal("Failed to get user by username: " + err.Error())
	}

	return &u, nil
}

// UpdatePassword updates a user's password hash in the PostgreSQL database.
// It also updates the updated_at timestamp to the current time.
// Returns NotFound error if the user doesn't exist, or Internal error if the update fails.
func (r *userRepository) UpdatePassword(ctx context.Context, id uint, passwordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $2, updated_at = $3
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id, passwordHash, time.Now())
	if err != nil {
		return errors.Internal("Failed to update password: " + err.Error())
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows: " + err.Error())
	}

	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("User with ID %d not found", id))
	}

	return nil
}

// UpdateLastLogin updates the last login timestamp for a user.
// This is typically called when a user successfully authenticates.
// Returns an error if the update fails, but does not return NotFound
// as this isn't considered a critical error.
func (r *userRepository) UpdateLastLogin(ctx context.Context, id uint) error {
	query := `
		UPDATE users
		SET last_login_at = $2
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, time.Now())
	if err != nil {
		return errors.Internal("Failed to update last login timestamp: " + err.Error())
	}

	return nil
}

// Delete removes a user from the PostgreSQL database by their ID.
// Returns NotFound error if the user doesn't exist, or Internal error if the deletion fails.
// This is a hard delete operation that permanently removes the user from the database.
func (r *userRepository) Delete(ctx context.Context, id uint) error {
	query := "DELETE FROM users WHERE id = $1"

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.Internal("Failed to delete user: " + err.Error())
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows after deletion: " + err.Error())
	}

	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("User with ID %d not found", id))
	}

	return nil
}
