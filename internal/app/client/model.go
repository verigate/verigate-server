package client

import (
	"time"
)

type Client struct {
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
	JwksURI         string    `json:"jwks_uri,omitempty"`
	Jwks            string    `json:"jwks,omitempty"`
	Contacts        []string  `json:"contacts,omitempty"`
	SoftwareID      string    `json:"software_id,omitempty"`
	SoftwareVersion string    `json:"software_version,omitempty"`
	IsConfidential  bool      `json:"is_confidential"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	OwnerID         uint      `json:"owner_id"`
}
