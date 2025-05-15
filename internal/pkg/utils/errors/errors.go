// Package errors provides custom error types and helper functions for
// standardized error handling across the application.
package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
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
