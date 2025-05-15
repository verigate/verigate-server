// Package user provides functionality for user account management including
// registration, authentication, profile management, and session handling.
package user

import (
	"time"
)

// User represents a user account in the system with profile and authentication information.
type User struct {
	ID                      uint       `json:"id"`                            // Primary key
	Username                string     `json:"username"`                      // Unique username
	Email                   string     `json:"email"`                         // User's email address
	PasswordHash            string     `json:"-"`                             // Hashed password, not exposed in JSON
	FullName                *string    `json:"full_name,omitempty"`           // User's full name (optional)
	ProfilePictureURL       *string    `json:"profile_picture_url,omitempty"` // URL to profile image (optional)
	PhoneNumber             *string    `json:"phone_number,omitempty"`        // Contact phone number (optional)
	IsActive                bool       `json:"is_active"`                     // Whether the account is active
	IsVerified              bool       `json:"is_verified"`                   // Whether the email has been verified
	VerificationToken       *string    `json:"-"`                             // Token for email verification, not exposed
	VerificationTokenExpiry *time.Time `json:"-"`                             // Expiry for verification token
	CreatedAt               time.Time  `json:"created_at"`                    // When the account was created
	UpdatedAt               time.Time  `json:"updated_at"`                    // When the account was last updated
	LastLoginAt             *time.Time `json:"last_login_at,omitempty"`       // When the user last logged in
}
