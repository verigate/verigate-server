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

type Service struct {
	repo        Repository
	authService *auth.Service
}

func NewService(repo Repository, authService *auth.Service) *Service {
	return &Service{
		repo:        repo,
		authService: authService,
	}
}

func (s *Service) Create(ctx context.Context, ownerID uint, req CreateClientRequest) (*ClientResponse, error) {
	// Generate client ID and secret
	clientID, err := s.generateClientID()
	if err != nil {
		return nil, errors.Internal("Failed to generate client ID")
	}

	var clientSecret string
	var hashedSecret string
	if req.IsConfidential {
		clientSecret, hashedSecret, err = s.generateClientSecret()
		if err != nil {
			return nil, errors.Internal("Failed to generate client secret")
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

func (s *Service) GetByID(ctx context.Context, id uint) (*ClientResponse, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.NotFound("Client not found")
	}

	return s.toResponse(client), nil
}

func (s *Service) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	client, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *Service) Update(ctx context.Context, id uint, ownerID uint, req UpdateClientRequest) error {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.NotFound("Client not found")
	}

	// Check ownership
	if client.OwnerID != ownerID {
		return errors.Forbidden("Not authorized to update this client")
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

func (s *Service) Delete(ctx context.Context, id uint, ownerID uint) error {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.NotFound("Client not found")
	}

	// Check ownership
	if client.OwnerID != ownerID {
		return errors.Forbidden("Not authorized to delete this client")
	}

	return s.repo.Delete(ctx, id)
}

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

func (s *Service) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	client, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.Unauthorized("Invalid client credentials")
	}

	if !client.IsActive {
		return nil, errors.Unauthorized("Client is not active")
	}

	// For confidential clients, verify secret
	if client.IsConfidential {
		if err := hash.CompareHashAndPassword(client.ClientSecret, clientSecret); err != nil {
			return nil, errors.Unauthorized("Invalid client credentials")
		}
	}

	return client, nil
}

// Helper methods

func (s *Service) generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

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
