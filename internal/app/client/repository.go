// Package client provides functionality for managing OAuth clients,
// including registration, configuration, and permission management.
package client

import (
	"context"
)

// Repository defines the interface for client-related data storage and retrieval.
// It handles CRUD operations for OAuth client applications.
type Repository interface {
	// Save creates a new OAuth client in the data store.
	// Returns an error if the operation fails, such as when a client ID already exists.
	Save(ctx context.Context, client *Client) error

	// Update modifies an existing OAuth client in the data store.
	// Returns an error if the client doesn't exist or the update fails.
	Update(ctx context.Context, client *Client) error

	// FindByID retrieves an OAuth client by its internal ID.
	// Returns nil if the client doesn't exist.
	FindByID(ctx context.Context, id uint) (*Client, error)

	// FindByClientID retrieves an OAuth client by its client ID (the public identifier).
	// Returns nil if the client doesn't exist.
	FindByClientID(ctx context.Context, clientID string) (*Client, error)

	// FindByOwnerID retrieves a paginated list of OAuth clients owned by a specific user.
	// Returns the clients, total count, and any error that occurred.
	FindByOwnerID(ctx context.Context, ownerID uint, page, limit int) ([]Client, int64, error)

	// Delete removes an OAuth client from the data store.
	// Returns an error if the client doesn't exist or the deletion fails.
	Delete(ctx context.Context, id uint) error

	// UpdateStatus changes the active status of an OAuth client.
	// This can be used to enable or disable a client without deleting it.
	// Returns an error if the client doesn't exist or the update fails.
	UpdateStatus(ctx context.Context, id uint, isActive bool) error
}
