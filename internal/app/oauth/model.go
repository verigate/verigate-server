package oauth

import (
	"time"
)

type AuthorizationCode struct {
	ID                  uint      `json:"id"`
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              uint      `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	IsUsed              bool      `json:"is_used"`
}

type UserConsent struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
