// Package oauth provides functionality for implementing OAuth 2.0 authorization flows,
// including authorization code, implicit, password, and client credentials.
package oauth

// AuthorizeRequest represents an OAuth 2.0 authorization request.
// This request initiates the authorization flow as defined in RFC 6749.
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required"` // Response type (code, token)
	ClientID            string `form:"client_id" binding:"required"`     // OAuth client identifier
	RedirectURI         string `form:"redirect_uri" binding:"required"`  // URI to redirect after authorization
	Scope               string `form:"scope"`                            // Requested permission scopes
	State               string `form:"state"`                            // Client state value for CSRF protection
	CodeChallenge       string `form:"code_challenge"`                   // PKCE code challenge
	CodeChallengeMethod string `form:"code_challenge_method"`            // PKCE challenge method (plain or S256)
}

// TokenRequest represents an OAuth 2.0 token request.
// This can be used for authorization code exchange, refresh token usage,
// client credentials, or password grant types.
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"` // Grant type (e.g., authorization_code, refresh_token)
	Code         string `form:"code"`                          // Authorization code (for authorization_code grant)
	RedirectURI  string `form:"redirect_uri"`                  // Must match the original redirect URI
	ClientID     string `form:"client_id"`                     // OAuth client identifier
	ClientSecret string `form:"client_secret"`                 // Client secret for confidential clients
	RefreshToken string `form:"refresh_token"`                 // Refresh token (for refresh_token grant)
	Scope        string `form:"scope"`                         // Requested permission scopes
	CodeVerifier string `form:"code_verifier"`                 // PKCE code verifier
}

// TokenResponse represents an OAuth 2.0 token response.
// This is returned when a token is successfully issued, as defined in RFC 6749 Section 5.1.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`            // The issued access token
	TokenType    string `json:"token_type"`              // Token type (typically "Bearer")
	ExpiresIn    int    `json:"expires_in"`              // Token lifetime in seconds
	RefreshToken string `json:"refresh_token,omitempty"` // Optional refresh token
	Scope        string `json:"scope,omitempty"`         // Scope of the access token
}

type RevokeRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"`
}

type UserInfoResponse struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

type ConsentPageData struct {
	ClientName     string   `json:"client_name"`
	ClientID       string   `json:"client_id"`
	RequestedScope string   `json:"requested_scope"`
	ScopeList      []string `json:"scope_list"`
	State          string   `json:"state"`
}
