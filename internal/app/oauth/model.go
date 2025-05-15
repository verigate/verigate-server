// Package oauth provides functionality for implementing OAuth 2.0 authorization flows,
// including authorization code, implicit, password, and client credentials.
package oauth

import (
	"time"
)

// AuthorizationCode represents an OAuth 2.0 authorization code stored in the database.
// Authorization codes are short-lived tokens issued during the authorization code flow,
// which can be exchanged for access and refresh tokens.
type AuthorizationCode struct {
	ID                  uint      `json:"id"`                              // Primary key
	Code                string    `json:"code"`                            // The authorization code value
	ClientID            string    `json:"client_id"`                       // Client the code was issued to
	UserID              uint      `json:"user_id"`                         // User who authorized the client
	RedirectURI         string    `json:"redirect_uri"`                    // URI to redirect to after authorization
	Scope               string    `json:"scope"`                           // Space-separated list of authorized scopes
	CodeChallenge       string    `json:"code_challenge,omitempty"`        // PKCE code challenge (optional)
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"` // PKCE challenge method (plain or S256)
	ExpiresAt           time.Time `json:"expires_at"`                      // Expiration timestamp
	CreatedAt           time.Time `json:"created_at"`                      // Creation timestamp
	IsUsed              bool      `json:"is_used"`                         // Whether the code has been used
}

// UserConsent represents a user's explicit permission for an OAuth client
// to access specific resources on their behalf with defined scopes.
type UserConsent struct {
	ID        uint      `json:"id"`         // Primary key
	UserID    uint      `json:"user_id"`    // User who granted consent
	ClientID  string    `json:"client_id"`  // OAuth client receiving consent
	Scope     string    `json:"scope"`      // Space-separated list of approved scopes
	CreatedAt time.Time `json:"created_at"` // When consent was first granted
	UpdatedAt time.Time `json:"updated_at"` // When consent was last updated
}
