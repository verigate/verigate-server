// Package client provides functionality for managing OAuth clients,
// including registration, configuration, and permission management.
package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/verigate/verigate-server/internal/app/auth"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/hash"
)

// Service provides business logic for managing OAuth clients.
// It handles client creation, retrieval, updating, deletion, and authentication.
type Service struct {
	repo        Repository
	authService *auth.Service
}

// NewService creates a new client service instance.
// It requires a client repository for data access and an auth service for authentication operations.
func NewService(repo Repository, authService *auth.Service) *Service {
	return &Service{
		repo:        repo,
		authService: authService,
	}
}

// Create registers a new OAuth client with the provided details.
// It generates a client ID and an optional client secret for confidential clients,
// then saves the client to the repository and returns the created client details.
// The client secret is only returned once at creation time.
func (s *Service) Create(ctx context.Context, ownerID uint, req CreateClientRequest) (*ClientResponse, error) {
	// Generate client ID and secret
	clientID, err := s.generateClientID()
	if err != nil {
		return nil, errors.Internal("Failed to generate client ID: " + err.Error())
	}

	var clientSecret string
	var hashedSecret string
	if req.IsConfidential {
		clientSecret, hashedSecret, err = s.generateClientSecret()
		if err != nil {
			return nil, errors.Internal("Failed to generate client secret: " + err.Error())
		}
	}

	// Create client model
	client := &Client{
		ClientID:        clientID,
		ClientSecret:    hashedSecret,
		ClientName:      req.ClientName,
		Description:     req.Description,
		ClientURI:       req.ClientURI,
		LogoURI:         req.LogoURI,
		RedirectURIs:    req.RedirectURIs,
		GrantTypes:      req.GrantTypes,
		ResponseTypes:   req.ResponseTypes,
		Scope:           req.Scope,
		TOSUri:          req.TOSUri,
		PolicyURI:       req.PolicyURI,
		JwksURI:         req.JwksURI,
		Jwks:            req.Jwks,
		Contacts:        req.Contacts,
		SoftwareID:      req.SoftwareID,
		SoftwareVersion: req.SoftwareVersion,
		IsConfidential:  req.IsConfidential,
		IsActive:        true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		OwnerID:         ownerID,
	}

	// Save to repository
	if err := s.repo.Save(ctx, client); err != nil {
		return nil, err
	}

	// Return response with unhashed secret (only time it's available)
	return &ClientResponse{
		ID:             client.ID,
		ClientID:       client.ClientID,
		ClientSecret:   clientSecret, // Return unhashed secret
		ClientName:     client.ClientName,
		Description:    client.Description,
		ClientURI:      client.ClientURI,
		LogoURI:        client.LogoURI,
		RedirectURIs:   client.RedirectURIs,
		GrantTypes:     client.GrantTypes,
		ResponseTypes:  client.ResponseTypes,
		Scope:          client.Scope,
		TOSUri:         client.TOSUri,
		PolicyURI:      client.PolicyURI,
		IsConfidential: client.IsConfidential,
		IsActive:       client.IsActive,
		CreatedAt:      client.CreatedAt,
		UpdatedAt:      client.UpdatedAt,
	}, nil
}

// GetByID retrieves a client by its internal ID.
// Returns the client details or an error if the client doesn't exist or can't be retrieved.
// The client secret is never returned in the response.
func (s *Service) GetByID(ctx context.Context, id uint) (*ClientResponse, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.NotFound(errors.ErrMsgClientNotFound)
	}

	return s.toResponse(client), nil
}

// GetByClientID retrieves a client by its client ID (public identifier).
// Returns the client entity or an error if the client doesn't exist or can't be retrieved.
// This method is primarily used for internal service operations.
func (s *Service) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	client, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Update modifies an existing OAuth client with the provided details.
// It verifies that the requesting user owns the client before making any changes.
// Only non-empty/non-zero fields in the request are updated.
// Returns an error if the client doesn't exist, the user doesn't own it,
// or if the update operation fails.
func (s *Service) Update(ctx context.Context, id uint, ownerID uint, req UpdateClientRequest) error {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.NotFound(errors.ErrMsgClientNotFound)
	}

	// Check ownership
	if client.OwnerID != ownerID {
		return errors.Forbidden(errors.ErrMsgNotAuthorizedForClient)
	}

	// Update fields if provided
	if req.ClientName != "" {
		client.ClientName = req.ClientName
	}
	if req.Description != "" {
		client.Description = req.Description
	}
	if req.ClientURI != "" {
		client.ClientURI = req.ClientURI
	}
	if req.LogoURI != "" {
		client.LogoURI = req.LogoURI
	}
	if len(req.RedirectURIs) > 0 {
		client.RedirectURIs = req.RedirectURIs
	}
	if len(req.GrantTypes) > 0 {
		client.GrantTypes = req.GrantTypes
	}
	if len(req.ResponseTypes) > 0 {
		client.ResponseTypes = req.ResponseTypes
	}
	if req.Scope != "" {
		client.Scope = req.Scope
	}
	client.TOSUri = req.TOSUri
	client.PolicyURI = req.PolicyURI
	client.JwksURI = req.JwksURI
	client.Jwks = req.Jwks
	client.Contacts = req.Contacts
	client.SoftwareID = req.SoftwareID
	client.SoftwareVersion = req.SoftwareVersion
	client.UpdatedAt = time.Now()

	return s.repo.Update(ctx, client)
}

// Delete removes an OAuth client if the requesting user owns it.
// It first verifies ownership before proceeding with deletion.
// Returns an error if the client doesn't exist, the user doesn't own it,
// or if the delete operation fails.
func (s *Service) Delete(ctx context.Context, id uint, ownerID uint) error {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.NotFound(errors.ErrMsgClientNotFound)
	}

	// Check ownership
	if client.OwnerID != ownerID {
		return errors.Forbidden(errors.ErrMsgNotAuthorizedToDeleteClient)
	}

	return s.repo.Delete(ctx, id)
}

// List retrieves all OAuth clients owned by the specified user with pagination.
// It returns client details along with pagination metadata.
// The page parameter is 1-indexed (first page is 1, not 0).
// Returns an error if the clients can't be retrieved.
func (s *Service) List(ctx context.Context, ownerID uint, page, limit int) (*ClientListResponse, error) {
	clients, total, err := s.repo.FindByOwnerID(ctx, ownerID, page, limit)
	if err != nil {
		return nil, err
	}

	var responses []ClientResponse
	for _, client := range clients {
		responses = append(responses, *s.toResponse(&client))
	}

	return &ClientListResponse{
		Clients: responses,
		Total:   total,
		Page:    page,
		PerPage: limit,
	}, nil
}

// ValidateClient verifies client credentials for authentication purposes.
// For confidential clients, it checks that the provided secret matches the stored hash.
// For public clients, it just verifies the client exists and is active.
// Returns the client if validation succeeds or an error if credentials are invalid or the client is inactive.
func (s *Service) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	client, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.Unauthorized(errors.ErrMsgInvalidClientCredentials)
	}

	if !client.IsActive {
		return nil, errors.Unauthorized(errors.ErrMsgClientNotActive)
	}

	// For confidential clients, verify secret
	if client.IsConfidential {
		if err := hash.CompareHashAndPassword(client.ClientSecret, clientSecret); err != nil {
			return nil, errors.Unauthorized(errors.ErrMsgInvalidClientCredentials)
		}
	}

	return client, nil
}

// Helper methods

// generateClientID creates a cryptographically secure random client ID.
// The ID is generated as a URL-safe base64 encoded string of 16 random bytes,
// resulting in a 22-character string.
func (s *Service) generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateClientSecret creates a cryptographically secure random client secret and its hash.
// Returns the raw secret (to be returned to the client only once), the hashed secret (for storage),
// and any error that occurred during generation.
// The secret is generated as a URL-safe base64 encoded string of 32 random bytes,
// resulting in a 43-character string.
func (s *Service) generateClientSecret() (string, string, error) {
	// Generate raw secret
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret := base64.URLEncoding.EncodeToString(b)

	// Hash the secret for storage
	hashedSecret, err := hash.HashPassword(secret)
	if err != nil {
		return "", "", err
	}

	return secret, hashedSecret, nil
}

func (s *Service) toResponse(client *Client) *ClientResponse {
	return &ClientResponse{
		ID:             client.ID,
		ClientID:       client.ClientID,
		ClientName:     client.ClientName,
		Description:    client.Description,
		ClientURI:      client.ClientURI,
		LogoURI:        client.LogoURI,
		RedirectURIs:   client.RedirectURIs,
		GrantTypes:     client.GrantTypes,
		ResponseTypes:  client.ResponseTypes,
		Scope:          client.Scope,
		TOSUri:         client.TOSUri,
		PolicyURI:      client.PolicyURI,
		IsConfidential: client.IsConfidential,
		IsActive:       client.IsActive,
		CreatedAt:      client.CreatedAt,
		UpdatedAt:      client.UpdatedAt,
	}
}
