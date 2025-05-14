package auth

import (
	"time"
)

// RefreshToken struct defines a refresh token used for the web app authentication system.
// This is kept separate from the OAuth token system.
type RefreshToken struct {
	ID        string    `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"-"` // Hashed token value
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IsRevoked bool      `json:"is_revoked"`
	UserAgent string    `json:"user_agent,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
}

// TokenPair struct for returning access and refresh token pairs.
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}
