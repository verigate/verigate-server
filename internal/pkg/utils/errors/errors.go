package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type CustomError struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

func (e CustomError) Error() string {
	if e.Details != nil {
		if details, err := json.Marshal(e.Details); err == nil {
			return fmt.Sprintf("status: %d, message: %s, details: %s", e.Status, e.Message, string(details))
		}
	}
	return fmt.Sprintf("status: %d, message: %s", e.Status, e.Message)
}

func (e CustomError) WithDetails(details interface{}) CustomError {
	e.Details = details
	return e
}

func (e CustomError) Is(target error) bool {
	t, ok := target.(CustomError)
	if !ok {
		return false
	}
	return e.Status == t.Status
}

func New(status int, message string) CustomError {
	return CustomError{
		Status:  status,
		Message: message,
	}
}

func BadRequest(message string) CustomError {
	return CustomError{
		Status:  http.StatusBadRequest,
		Message: message,
	}
}

func Unauthorized(message string) CustomError {
	return CustomError{
		Status:  http.StatusUnauthorized,
		Message: message,
	}
}

func Forbidden(message string) CustomError {
	return CustomError{
		Status:  http.StatusForbidden,
		Message: message,
	}
}

func NotFound(message string) CustomError {
	return CustomError{
		Status:  http.StatusNotFound,
		Message: message,
	}
}

func Conflict(message string) CustomError {
	return CustomError{
		Status:  http.StatusConflict,
		Message: message,
	}
}

func UnprocessableEntity(message string) CustomError {
	return CustomError{
		Status:  http.StatusUnprocessableEntity,
		Message: message,
	}
}

func TooManyRequests(message string) CustomError {
	return CustomError{
		Status:  http.StatusTooManyRequests,
		Message: message,
	}
}

func Internal(message string) CustomError {
	return CustomError{
		Status:  http.StatusInternalServerError,
		Message: message,
	}
}

func ServiceUnavailable(message string) CustomError {
	return CustomError{
		Status:  http.StatusServiceUnavailable,
		Message: message,
	}
}
