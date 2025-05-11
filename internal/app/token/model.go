package token

import (
	"time"
)

type AccessToken struct {
	ID         uint      `json:"id"`
	TokenID    string    `json:"token_id"`
	TokenHash  string    `json:"-"`
	ClientID   string    `json:"client_id"`
	UserID     uint      `json:"user_id"`
	Scope      string    `json:"scope"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	IsRevoked  bool      `json:"is_revoked"`
}

type RefreshToken struct {
	ID            uint      `json:"id"`
	TokenID       string    `json:"token_id"`
	TokenHash     string    `json:"-"`
	AccessTokenID string    `json:"access_token_id,omitempty"`
	ClientID      string    `json:"client_id"`
	UserID        uint      `json:"user_id"`
	Scope         string    `json:"scope"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	IsRevoked     bool      `json:"is_revoked"`
}
