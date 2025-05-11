package postgres

import (
	"context"
	"database/sql"

	"github.com/lib/pq"
	"github.com/verigate/verigate-server/internal/app/client"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

type clientRepository struct {
	db *sql.DB
}

func NewClientRepository(db *sql.DB) client.Repository {
	return &clientRepository{db: db}
}

func (r *clientRepository) Save(ctx context.Context, client *client.Client) error {
	query := `
		INSERT INTO clients (
			client_id, client_secret, client_name, description, client_uri, logo_uri,
			redirect_uris, grant_types, response_types, scope, tos_uri, policy_uri,
			jwks_uri, jwks, contacts, software_id, software_version,
			is_confidential, is_active, created_at, updated_at, owner_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
		) RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		client.ClientID,
		client.ClientSecret,
		client.ClientName,
		client.Description,
		client.ClientURI,
		client.LogoURI,
		pq.Array(client.RedirectURIs),
		pq.Array(client.GrantTypes),
		pq.Array(client.ResponseTypes),
		client.Scope,
		client.TOSUri,
		client.PolicyURI,
		client.JwksURI,
		client.Jwks,
		pq.Array(client.Contacts),
		client.SoftwareID,
		client.SoftwareVersion,
		client.IsConfidential,
		client.IsActive,
		client.CreatedAt,
		client.UpdatedAt,
		client.OwnerID,
	).Scan(&client.ID)

	if err != nil {
		return errors.Internal("Failed to create client")
	}

	return nil
}

func (r *clientRepository) Update(ctx context.Context, client *client.Client) error {
	query := `
		UPDATE clients SET
			client_name = $2, description = $3, client_uri = $4, logo_uri = $5,
			redirect_uris = $6, grant_types = $7, response_types = $8, scope = $9,
			tos_uri = $10, policy_uri = $11, jwks_uri = $12, jwks = $13,
			contacts = $14, software_id = $15, software_version = $16,
			updated_at = $17
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		client.ID,
		client.ClientName,
		client.Description,
		client.ClientURI,
		client.LogoURI,
		pq.Array(client.RedirectURIs),
		pq.Array(client.GrantTypes),
		pq.Array(client.ResponseTypes),
		client.Scope,
		client.TOSUri,
		client.PolicyURI,
		client.JwksURI,
		client.Jwks,
		pq.Array(client.Contacts),
		client.SoftwareID,
		client.SoftwareVersion,
		client.UpdatedAt,
	)

	if err != nil {
		return errors.Internal("Failed to update client")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("Client not found")
	}

	return nil
}

func (r *clientRepository) FindByID(ctx context.Context, id uint) (*client.Client, error) {
	var c client.Client
	query := `
		SELECT id, client_id, client_secret, client_name, description, client_uri, logo_uri,
		       redirect_uris, grant_types, response_types, scope, tos_uri, policy_uri,
		       jwks_uri, jwks, contacts, software_id, software_version,
		       is_confidential, is_active, created_at, updated_at, owner_id
		FROM clients WHERE id = $1
	`

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&c.ID,
		&c.ClientID,
		&c.ClientSecret,
		&c.ClientName,
		&c.Description,
		&c.ClientURI,
		&c.LogoURI,
		pq.Array(&c.RedirectURIs),
		pq.Array(&c.GrantTypes),
		pq.Array(&c.ResponseTypes),
		&c.Scope,
		&c.TOSUri,
		&c.PolicyURI,
		&c.JwksURI,
		&c.Jwks,
		pq.Array(&c.Contacts),
		&c.SoftwareID,
		&c.SoftwareVersion,
		&c.IsConfidential,
		&c.IsActive,
		&c.CreatedAt,
		&c.UpdatedAt,
		&c.OwnerID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal("Failed to get client")
	}

	return &c, nil
}

func (r *clientRepository) FindByClientID(ctx context.Context, clientID string) (*client.Client, error) {
	var c client.Client
	query := `
		SELECT id, client_id, client_secret, client_name, description, client_uri, logo_uri,
		       redirect_uris, grant_types, response_types, scope, tos_uri, policy_uri,
		       jwks_uri, jwks, contacts, software_id, software_version,
		       is_confidential, is_active, created_at, updated_at, owner_id
		FROM clients WHERE client_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, clientID).Scan(
		&c.ID,
		&c.ClientID,
		&c.ClientSecret,
		&c.ClientName,
		&c.Description,
		&c.ClientURI,
		&c.LogoURI,
		pq.Array(&c.RedirectURIs),
		pq.Array(&c.GrantTypes),
		pq.Array(&c.ResponseTypes),
		&c.Scope,
		&c.TOSUri,
		&c.PolicyURI,
		&c.JwksURI,
		&c.Jwks,
		pq.Array(&c.Contacts),
		&c.SoftwareID,
		&c.SoftwareVersion,
		&c.IsConfidential,
		&c.IsActive,
		&c.CreatedAt,
		&c.UpdatedAt,
		&c.OwnerID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal("Failed to get client by client_id")
	}

	return &c, nil
}

func (r *clientRepository) FindByOwnerID(ctx context.Context, ownerID uint, page, limit int) ([]client.Client, int64, error) {
	offset := (page - 1) * limit

	// Get total count
	var total int64
	countQuery := "SELECT COUNT(*) FROM clients WHERE owner_id = $1"
	if err := r.db.QueryRowContext(ctx, countQuery, ownerID).Scan(&total); err != nil {
		return nil, 0, errors.Internal("Failed to count clients")
	}

	// Get clients with pagination
	query := `
		SELECT id, client_id, client_secret, client_name, description, client_uri, logo_uri,
		       redirect_uris, grant_types, response_types, scope, tos_uri, policy_uri,
		       jwks_uri, jwks, contacts, software_id, software_version,
		       is_confidential, is_active, created_at, updated_at, owner_id
		FROM clients
		WHERE owner_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, ownerID, limit, offset)
	if err != nil {
		return nil, 0, errors.Internal("Failed to get clients")
	}
	defer rows.Close()

	var clients []client.Client
	for rows.Next() {
		var c client.Client
		if err := rows.Scan(
			&c.ID,
			&c.ClientID,
			&c.ClientSecret,
			&c.ClientName,
			&c.Description,
			&c.ClientURI,
			&c.LogoURI,
			pq.Array(&c.RedirectURIs),
			pq.Array(&c.GrantTypes),
			pq.Array(&c.ResponseTypes),
			&c.Scope,
			&c.TOSUri,
			&c.PolicyURI,
			&c.JwksURI,
			&c.Jwks,
			pq.Array(&c.Contacts),
			&c.SoftwareID,
			&c.SoftwareVersion,
			&c.IsConfidential,
			&c.IsActive,
			&c.CreatedAt,
			&c.UpdatedAt,
			&c.OwnerID,
		); err != nil {
			return nil, 0, errors.Internal("Failed to scan client")
		}
		clients = append(clients, c)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Internal("Error iterating clients")
	}

	return clients, total, nil
}

func (r *clientRepository) Delete(ctx context.Context, id uint) error {
	query := "DELETE FROM clients WHERE id = $1"

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.Internal("Failed to delete client")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("Client not found")
	}

	return nil
}

func (r *clientRepository) UpdateStatus(ctx context.Context, id uint, isActive bool) error {
	query := `
		UPDATE clients
		SET is_active = $2, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id, isActive)
	if err != nil {
		return errors.Internal("Failed to update client status")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Internal("Failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("Client not found")
	}

	return nil
}
