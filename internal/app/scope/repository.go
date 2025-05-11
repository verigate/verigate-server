package scope

import (
	"context"
)

type Repository interface {
	Save(ctx context.Context, scope *Scope) error
	FindByName(ctx context.Context, name string) (*Scope, error)
	FindByNames(ctx context.Context, names []string) ([]Scope, error)
	FindAll(ctx context.Context) ([]Scope, error)
	FindDefaults(ctx context.Context) ([]Scope, error)
}
