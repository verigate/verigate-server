package client

import "time"

type CreateClientRequest struct {
	ClientName      string   `json:"client_name" binding:"required"`
	Description     string   `json:"description"`
	ClientURI       string   `json:"client_uri"`
	LogoURI         string   `json:"logo_uri"`
	RedirectURIs    []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes      []string `json:"grant_types" binding:"required,min=1"`
	ResponseTypes   []string `json:"response_types"`
	Scope           string   `json:"scope" binding:"required"`
	TOSUri          string   `json:"tos_uri"`
	PolicyURI       string   `json:"policy_uri"`
	JwksURI         string   `json:"jwks_uri"`
	Jwks            string   `json:"jwks"`
	Contacts        []string `json:"contacts"`
	SoftwareID      string   `json:"software_id"`
	SoftwareVersion string   `json:"software_version"`
	IsConfidential  bool     `json:"is_confidential"`
}

type UpdateClientRequest struct {
	ClientName      string   `json:"client_name"`
	Description     string   `json:"description"`
	ClientURI       string   `json:"client_uri"`
	LogoURI         string   `json:"logo_uri"`
	RedirectURIs    []string `json:"redirect_uris"`
	GrantTypes      []string `json:"grant_types"`
	ResponseTypes   []string `json:"response_types"`
	Scope           string   `json:"scope"`
	TOSUri          string   `json:"tos_uri"`
	PolicyURI       string   `json:"policy_uri"`
	JwksURI         string   `json:"jwks_uri"`
	Jwks            string   `json:"jwks"`
	Contacts        []string `json:"contacts"`
	SoftwareID      string   `json:"software_id"`
	SoftwareVersion string   `json:"software_version"`
}

type ClientResponse struct {
	ID              uint      `json:"id"`
	ClientID        string    `json:"client_id"`
	ClientSecret    string    `json:"client_secret,omitempty"`
	ClientName      string    `json:"client_name"`
	Description     string    `json:"description,omitempty"`
	ClientURI       string    `json:"client_uri,omitempty"`
	LogoURI         string    `json:"logo_uri,omitempty"`
	RedirectURIs    []string  `json:"redirect_uris"`
	GrantTypes      []string  `json:"grant_types"`
	ResponseTypes   []string  `json:"response_types,omitempty"`
	Scope           string    `json:"scope"`
	TOSUri          string    `json:"tos_uri,omitempty"`
	PolicyURI       string    `json:"policy_uri,omitempty"`
	IsConfidential  bool      `json:"is_confidential"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type ClientListResponse struct {
	Clients []ClientResponse `json:"clients"`
	Total   int64           `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
}
