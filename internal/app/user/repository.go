// Package user provides functionality for user account management including
// registration, authentication, profile management, and session handling.
package user

import (
	"context"
)

// Repository defines the interface for user data access operations.
// It provides methods for creating, retrieving, updating, and deleting user accounts.
type Repository interface {
	// Save creates a new user record in the data store
	Save(ctx context.Context, user *User) error

	// Update modifies an existing user's profile information
	Update(ctx context.Context, user *User) error

	// FindByID retrieves a user by their unique ID
	FindByID(ctx context.Context, id uint) (*User, error)

	// FindByEmail retrieves a user by their email address
	FindByEmail(ctx context.Context, email string) (*User, error)

	// FindByUsername retrieves a user by their username
	FindByUsername(ctx context.Context, username string) (*User, error)

	// UpdatePassword changes a user's password hash
	UpdatePassword(ctx context.Context, id uint, passwordHash string) error

	// UpdateLastLogin updates the user's last login timestamp
	UpdateLastLogin(ctx context.Context, id uint) error

	// Delete removes a user account from the data store
	Delete(ctx context.Context, id uint) error
}
