package oauth

import (
	"context"
)

type Repository interface {
	// Authorization code methods
	SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	FindAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	MarkCodeAsUsed(ctx context.Context, code string) error
	DeleteExpiredCodes(ctx context.Context) error

	// User consent methods
	SaveUserConsent(ctx context.Context, consent *UserConsent) error
	FindUserConsent(ctx context.Context, userID uint, clientID string) (*UserConsent, error)
	UpdateUserConsent(ctx context.Context, consent *UserConsent) error
	DeleteUserConsent(ctx context.Context, userID uint, clientID string) error
}
