// Package auth provides authentication and authorization services
// for the application, including token generation, validation,
// and management of authentication sessions.
package auth

import (
	"time"
)

// RefreshToken defines a refresh token used for the web app authentication system.
// This is kept separate from the OAuth token system to provide independent
// authentication mechanisms for platform users versus OAuth clients.
type RefreshToken struct {
	ID        string    `json:"id"`                   // Unique identifier for the token
	UserID    uint      `json:"user_id"`              // User the token was issued to
	Token     string    `json:"-"`                    // Hashed token value, not exposed in JSON
	ExpiresAt time.Time `json:"expires_at"`           // Expiration timestamp
	CreatedAt time.Time `json:"created_at"`           // Creation timestamp
	IsRevoked bool      `json:"is_revoked"`           // Whether the token has been revoked
	UserAgent string    `json:"user_agent,omitempty"` // Client user agent for audit
	IPAddress string    `json:"ip_address,omitempty"` // Client IP address for audit
}

// TokenPair represents an access token and refresh token pair
// returned to clients during authentication operations.
type TokenPair struct {
	AccessToken           string    `json:"access_token"`             // JWT access token
	RefreshToken          string    `json:"refresh_token"`            // Refresh token for obtaining new tokens
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`  // When the access token expires
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"` // When the refresh token expires
}
