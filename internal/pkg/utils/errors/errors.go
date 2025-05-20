// Package errors provides custom error types and helper functions for
// standardized error handling across the application.
package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Common error message constants to ensure consistency
const (
	// Authentication related errors
	ErrMsgInvalidToken         = "invalid token"
	ErrMsgInvalidTokenClaims   = "invalid token claims"
	ErrMsgInvalidTokenID       = "invalid token ID"
	ErrMsgInvalidTokenFormat   = "invalid token format"
	ErrMsgInvalidTokenType     = "invalid token type"
	ErrMsgInvalidTokenIssuer   = "invalid token issuer"
	ErrMsgInvalidUserID        = "invalid user ID in token"
	ErrMsgTokenRevoked         = "token has been revoked"
	ErrMsgTokenExpired         = "token has expired"
	ErrMsgTokenNotFound        = "token not found"
	ErrMsgRefreshTokenNotFound = "refresh token not found"
	ErrMsgAccessTokenNotFound  = "access token not found"

	// Hash-related errors
	ErrMsgFailedToHashPassword     = "failed to hash password"
	ErrMsgFailedToHashToken        = "failed to hash token"
	ErrMsgFailedToHashAccessToken  = "failed to hash access token"
	ErrMsgFailedToHashRefreshToken = "failed to hash refresh token"

	// Database-related errors
	ErrMsgFailedToSaveAccessToken   = "failed to save access token"
	ErrMsgFailedToSaveRefreshToken  = "failed to save refresh token"
	ErrMsgFailedToFindAccessToken   = "failed to find access token"
	ErrMsgFailedToCountAccessTokens = "failed to count access tokens"
	ErrMsgFailedToGetAccessTokens   = "failed to get access tokens"
	ErrMsgFailedToCreateUser        = "failed to create user"
	ErrMsgFailedToUpdateUser        = "failed to update user"
	ErrMsgFailedToGetUserByID       = "failed to get user by ID"
	ErrMsgFailedToGetUserByEmail    = "failed to get user by email"
	ErrMsgFailedToGetUserByUsername = "failed to get user by username"
	ErrMsgFailedToUpdatePassword    = "failed to update password"
	ErrMsgFailedToDeleteUser        = "failed to delete user"
	ErrMsgFailedToGetAffectedRows   = "failed to get affected rows"

	// OAuth-related errors
	ErrMsgUnsupportedResponseType = "unsupported_response_type"
	ErrMsgInvalidClient           = "invalid_client"
	ErrMsgInvalidGrant            = "invalid_grant"
	ErrMsgAccessDenied            = "access_denied"
	ErrMsgUserDeniedAccess        = "user denied access"

	// User-related errors
	ErrMsgInvalidRequestFormat   = "invalid request format"
	ErrMsgEmailAlreadyRegistered = "email already registered"
	ErrMsgUsernameAlreadyTaken   = "username already taken"
	ErrMsgInvalidCredentials     = "invalid credentials"
	ErrMsgAccountNotActive       = "account is not active"
	ErrMsgUserNotFound           = "user not found"
	ErrMsgIncorrectPassword      = "incorrect password"

	// Token-related errors
	ErrMsgTokenIdRequired               = "token ID is required"
	ErrMsgFailedToGenerateAccessToken   = "failed to generate access token"
	ErrMsgFailedToGenerateRefreshToken  = "failed to generate refresh token"
	ErrMsgRefreshTokenNotIssuedToClient = "refresh token was not issued to this client"
	ErrMsgRequestedScopeExceedsOriginal = "requested scope exceeds original scope"
	ErrMsgTokenNotBelongToClient        = "token does not belong to client"
	ErrMsgNotAuthorizedToRevokeToken    = "not authorized to revoke this token"

	// Client-related errors
	ErrMsgClientNotFound              = "client not found"
	ErrMsgInvalidClientId             = "invalid client ID: must be a positive integer"
	ErrMsgClientIdAlreadyExists       = "client with this client_id already exists"
	ErrMsgInvalidClientCredentials    = "invalid client credentials"
	ErrMsgClientNotActive             = "client is not active"
	ErrMsgNotAuthorizedForClient      = "not authorized to update this client"
	ErrMsgNotAuthorizedToDeleteClient = "not authorized to delete this client"

	// OAuth-related additional errors
	ErrMsgAuthorizationCodeNotFound  = "authorization code not found"
	ErrMsgInvalidRedirectUri         = "invalid_redirect_uri"
	ErrMsgInvalidCodeChallengeMethod = "invalid_code_challenge_method"
	ErrMsgInvalidScope               = "invalid_scope"
	ErrMsgFailedToGenerateAuthCode   = "failed to generate authorization code"
	ErrMsgFailedToSaveAuthCode       = "failed to save authorization code"
	ErrMsgUnsupportedGrantType       = "unsupported_grant_type"
	ErrMsgInvalidRequest             = "invalid_request"
	ErrMsgFailedToGetAuthCode        = "failed to get authorization code"
	ErrMsgFailedToMarkCodeAsUsed     = "failed to mark code as used"
	ErrMsgFailedToDeleteExpiredCodes = "failed to delete expired codes"
	ErrMsgInvalidBasicAuthFormat     = "invalid basic auth format"
	ErrMsgMissingClientId            = "missing client_id"

	// IP control errors
	ErrMsgAccessDeniedIp    = "access denied from your IP address"
	ErrMsgIpNotAuthorized   = "your IP address is not authorized"
	ErrMsgRateLimitExceeded = "rate limit exceeded"

	// Database operation errors
	ErrMsgFailedToSaveUserConsent              = "failed to save user consent"
	ErrMsgFailedToScanAccessToken              = "failed to scan access token"
	ErrMsgErrorIteratingAccessTokens           = "error iterating access tokens"
	ErrMsgFailedToRevokeAccessToken            = "failed to revoke access token"
	ErrMsgFailedToRevokeAccessTokens           = "failed to revoke access tokens"
	ErrMsgFailedToRevokeAccessTokensByAuthCode = "failed to revoke access tokens by auth code"
	ErrMsgFailedToCheckTokenRevocationStatus   = "failed to check token revocation status"
	ErrMsgFailedToScanRefreshToken             = "failed to scan refresh token"
	ErrMsgErrorIteratingRefreshTokens          = "error iterating refresh tokens"
	ErrMsgFailedToRevokeRefreshToken           = "failed to revoke refresh token"
	ErrMsgFailedToRevokeRefreshTokens          = "failed to revoke refresh tokens"
	ErrMsgFailedToFindAuthCode                 = "Failed to find authorization code"
	ErrMsgFailedToUpdateUserConsent            = "Failed to update user consent"
	ErrMsgUserConsentNotFoundForUser           = "User consent not found for user ID %d"
	ErrMsgUserConsentNotFoundForClient         = "User consent not found for client ID %s"
	ErrMsgUserConsentNotFoundForUserAndClient  = "User consent not found for user ID %d and client ID %s"
	ErrMsgFailedToDeleteUserConsent            = "Failed to delete user consent"
	ErrMsgFailedToFindUserConsent              = "Failed to find user consent"
	ErrMsgFailedToFindRefreshTokenByHash       = "failed to find refresh token by hash"
	ErrMsgFailedToCountRefreshTokens           = "failed to count refresh tokens"
	ErrMsgFailedToGetRefreshTokens             = "failed to get refresh tokens"
	ErrMsgFailedToFindRefreshToken             = "failed to find refresh token"

	// Client Repository Errors
	ErrMsgFailedToCreateClient             = "Failed to create client"
	ErrMsgFailedToUpdateClient             = "Failed to update client"
	ErrMsgFailedToGetClientByID            = "Failed to get client by ID"
	ErrMsgFailedToGetClientByClientID      = "Failed to get client by client_id"
	ErrMsgFailedToCountClients             = "Failed to count clients"
	ErrMsgFailedToRetrieveClientsByOwnerID = "Failed to retrieve clients by owner ID"
	ErrMsgFailedToScanClientData           = "Failed to scan client data"
	ErrMsgErrorIteratingClientResults      = "Error iterating client results"
	ErrMsgFailedToDeleteClient             = "Failed to delete client"
	ErrMsgFailedToUpdateClientStatus       = "Failed to update client status"
	ErrMsgClientWithIDNotFound             = "Client with ID %d not found"

	// User Repository Errors

	// Scope Repository Errors
	ErrMsgFailedToFindScopeByName           = "Failed to find scope by name '%s': %s"
	ErrMsgFailedToSaveScope                 = "Failed to save scope"
	ErrMsgFailedToFindScopesByNames         = "Failed to find scopes by names"
	ErrMsgFailedToScanScopeData             = "Failed to scan scope data"
	ErrMsgErrorIteratingScopeResults        = "Error iterating scope results"
	ErrMsgFailedToFindAllScopes             = "Failed to find all scopes"
	ErrMsgFailedToFindDefaultScopes         = "Failed to find default scopes"
	ErrMsgFailedToScanDefaultScopeData      = "Failed to scan default scope data"
	ErrMsgErrorIteratingDefaultScopeResults = "Error iterating default scope results"

	// Redis cache errors
	ErrMsgFailedToMarshalRefreshToken        = "failed to marshal refresh token"
	ErrMsgFailedToUnmarshalRefreshToken      = "failed to unmarshal refresh token"
	ErrMsgFailedToMarshalUpdatedRefreshToken = "failed to marshal updated refresh token"
	ErrMsgFailedToGetRefreshToken            = "failed to get refresh token"

	// Generic errors
	ErrMsgInternalServerError = "internal_server_error"
	ErrMsgUnexpectedError     = "an unexpected error occurred"
)

// CustomError represents a structured error with HTTP status code and optional details.
// It implements the standard error interface and provides additional context for API responses.
type CustomError struct {
	Status  int         `json:"status"`            // HTTP status code
	Message string      `json:"message"`           // Error message
	Details interface{} `json:"details,omitempty"` // Additional error details
}

// Error returns a string representation of the error, implementing the error interface.
// If details are present, they will be included in the string representation.
func (e CustomError) Error() string {
	if e.Details != nil {
		if details, err := json.Marshal(e.Details); err == nil {
			return fmt.Sprintf("status: %d, message: %s, details: %s", e.Status, e.Message, string(details))
		}
		return fmt.Sprintf("status: %d, message: %s, details: (marshalling failed)", e.Status, e.Message) // Indicate marshalling failure
	}
	return fmt.Sprintf("status: %d, message: %s", e.Status, e.Message)
}

// WithDetails attaches additional information to the error.
// This is useful for including field validation errors or other context-specific details.
func (e CustomError) WithDetails(details interface{}) CustomError {
	e.Details = details
	return e
}

// Is implements error comparison for the errors.Is function.
// Two CustomErrors are considered equal if they have the same Status.
func (e CustomError) Is(target error) bool {
	t, ok := target.(CustomError)
	if !ok {
		return false
	}
	return e.Status == t.Status
}

// New creates a custom error with the specified HTTP status code and message.
func New(status int, message string) CustomError {
	return CustomError{
		Status:  status,
		Message: message,
	}
}

// BadRequest creates a 400 Bad Request error with the specified message.
// Use this for client errors like invalid input format or missing required fields.
func BadRequest(message string) CustomError {
	return CustomError{
		Status:  http.StatusBadRequest,
		Message: message,
	}
}

// Unauthorized creates a 401 Unauthorized error with the specified message.
// Use this for authentication failures like invalid credentials or expired tokens.
func Unauthorized(message string) CustomError {
	return CustomError{
		Status:  http.StatusUnauthorized,
		Message: message,
	}
}

// Forbidden creates a 403 Forbidden error with the specified message.
// Use this when authentication succeeded but the authenticated user doesn't have permission.
func Forbidden(message string) CustomError {
	return CustomError{
		Status:  http.StatusForbidden,
		Message: message,
	}
}

// NotFound creates a 404 Not Found error with the specified message.
// Use this when a requested resource doesn't exist.
func NotFound(message string) CustomError {
	return CustomError{
		Status:  http.StatusNotFound,
		Message: message,
	}
}

// Conflict creates a 409 Conflict error with the specified message.
// Use this for resource conflicts like duplicate unique keys or competing updates.
func Conflict(message string) CustomError {
	return CustomError{
		Status:  http.StatusConflict,
		Message: message,
	}
}

// UnprocessableEntity creates a 422 Unprocessable Entity error with the specified message.
// Use this when the request format is valid but the content is semantically incorrect.
func UnprocessableEntity(message string) CustomError {
	return CustomError{
		Status:  http.StatusUnprocessableEntity,
		Message: message,
	}
}

// TooManyRequests creates a 429 Too Many Requests error with the specified message.
// Use this when the client has sent too many requests in a given amount of time.
func TooManyRequests(message string) CustomError {
	return CustomError{
		Status:  http.StatusTooManyRequests,
		Message: message,
	}
}

// Internal creates a 500 Internal Server Error with the specified message.
// Use this for unexpected server-side errors that should be logged and investigated.
func Internal(message string) CustomError {
	return CustomError{
		Status:  http.StatusInternalServerError,
		Message: message,
	}
}

// ServiceUnavailable creates a 503 Service Unavailable error with the specified message.
// Use this when the service is temporarily unavailable (maintenance or overload).
func ServiceUnavailable(message string) CustomError {
	return CustomError{
		Status:  http.StatusServiceUnavailable,
		Message: message,
	}
}
