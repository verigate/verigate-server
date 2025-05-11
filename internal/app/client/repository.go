package client

import (
	"context"
)

type Repository interface {
	Save(ctx context.Context, client *Client) error
	Update(ctx context.Context, client *Client) error
	FindByID(ctx context.Context, id uint) (*Client, error)
	FindByClientID(ctx context.Context, clientID string) (*Client, error)
	FindByOwnerID(ctx context.Context, ownerID uint, page, limit int) ([]Client, int64, error)
	Delete(ctx context.Context, id uint) error
	UpdateStatus(ctx context.Context, id uint, isActive bool) error
}
