// Package user provides functionality for user account management including
// registration, authentication, profile management, and session handling.
package user

import "time"

// RegisterRequest represents the data needed to create a new user account.
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"` // Username (required, 3-50 chars)
	Email    string `json:"email" binding:"required,email"`           // Email address (required, valid format)
	Password string `json:"password" binding:"required,min=8"`        // Password (required, min 8 chars)
	FullName string `json:"full_name"`                                // Optional full name
}

// LoginRequest represents the data needed for user authentication.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"` // Email address (required, valid format)
	Password string `json:"password" binding:"required"`    // Password (required)
}

// UpdateUserRequest represents the data for updating a user's profile.
type UpdateUserRequest struct {
	FullName          string `json:"full_name"`           // New full name
	ProfilePictureURL string `json:"profile_picture_url"` // New profile picture URL
	PhoneNumber       string `json:"phone_number"`        // New phone number
}

// ChangePasswordRequest represents the data needed for changing a password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`       // Current password (required)
	NewPassword string `json:"new_password" binding:"required,min=8"` // New password (required, min 8 chars)
}

// UserResponse represents the user data returned in API responses.
// It excludes sensitive information like passwords and internal tokens.
type UserResponse struct {
	ID                uint       `json:"id"`                            // User identifier
	Username          string     `json:"username"`                      // Username
	Email             string     `json:"email"`                         // Email address
	FullName          *string    `json:"full_name,omitempty"`           // Optional full name
	ProfilePictureURL *string    `json:"profile_picture_url,omitempty"` // Optional profile picture URL
	PhoneNumber       *string    `json:"phone_number,omitempty"`        // Optional phone number
	IsActive          bool       `json:"is_active"`                     // Account active status
	IsVerified        bool       `json:"is_verified"`                   // Email verification status
	CreatedAt         time.Time  `json:"created_at"`                    // Account creation time
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`       // Last login time
}

// LoginResponse is returned after a successful login.
// It contains user information and authentication tokens.
type LoginResponse struct {
	User         UserResponse `json:"user"`          // User profile information
	AccessToken  string       `json:"access_token"`  // JWT access token
	RefreshToken string       `json:"refresh_token"` // Refresh token for obtaining new access tokens
	ExpiresAt    time.Time    `json:"expires_at"`    // When the access token expires
}

// RefreshTokenRequest is the structure for token refresh requests.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"` // Refresh token (required)
}

// RefreshTokenResponse is returned after a successful token refresh.
type RefreshTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}
