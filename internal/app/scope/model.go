// Package scope provides functionality for managing OAuth scopes,
// including scope registration, retrieval and validation.
package scope

import (
	"time"
)

// Scope represents an OAuth permission scope stored in the database.
type Scope struct {
	ID          uint      `json:"id"`          // Primary key
	Name        string    `json:"name"`        // Unique scope identifier (e.g., "profile", "email")
	Description string    `json:"description"` // Human-readable description of the permission
	IsDefault   bool      `json:"is_default"`  // Whether this scope is granted by default
	CreatedAt   time.Time `json:"created_at"`  // Creation timestamp
	UpdatedAt   time.Time `json:"updated_at"`  // Last update timestamp
}
