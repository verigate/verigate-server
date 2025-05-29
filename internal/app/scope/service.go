// Package scope provides functionality for managing OAuth scopes,
// including scope registration, retrieval and validation.
package scope

import (
	"context"
	"strings"

	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

// Service handles scope-related operations including validation,
// retrieval, and management of OAuth permission scopes.
type Service struct {
	repo Repository
}

// NewService creates a new scope service instance with the given repository.
// The repository is used for persistence operations related to scopes.
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// ValidateScope checks if all requested scopes are allowed and exist in the system.
// It takes a space-separated list of requested scopes and allowed scopes,
// and verifies that all requested scopes are both allowed and registered in the database.
// Returns true if all scopes are valid, false if any scope is invalid or not allowed.
func (s *Service) ValidateScope(ctx context.Context, requested, allowed string) (bool, error) {
	requestedScopes := strings.Split(requested, " ")
	allowedScopes := strings.Split(allowed, " ")

	// Check if all requested scopes are allowed
	for _, reqScope := range requestedScopes {
		found := false
		for _, allowScope := range allowedScopes {
			if reqScope == allowScope {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	// Verify all requested scopes exist in the system
	existingScopes, err := s.repo.FindByNames(ctx, requestedScopes)
	if err != nil {
		return false, errors.Internal(errors.ErrMsgFailedToFindScopesByNames)
	}

	// Create a map of existing scope names for quick lookup
	existingScopeMap := make(map[string]bool)
	for _, scope := range existingScopes {
		existingScopeMap[scope.Name] = true
	}

	// Check if all requested scopes exist
	for _, reqScope := range requestedScopes {
		if !existingScopeMap[reqScope] {
			return false, nil
		}
	}

	return true, nil
}

func (s *Service) GetDefaultScopes(ctx context.Context) ([]string, error) {
	scopes, err := s.repo.FindDefaults(ctx)
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToFindDefaultScopes)
	}

	var scopeNames []string
	for _, scope := range scopes {
		scopeNames = append(scopeNames, scope.Name)
	}

	return scopeNames, nil
}

func (s *Service) GetAllScopes(ctx context.Context) ([]Scope, error) {
	scopes, err := s.repo.FindAll(ctx)
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToFindAllScopes)
	}
	return scopes, nil
}

// ValidateScopeFormat checks if the scope string has a valid format.
// Scopes should be space-separated strings containing only valid characters.
func (s *Service) ValidateScopeFormat(scope string) error {
	if scope == "" {
		return errors.BadRequest(errors.ErrMsgInvalidScopeFormat)
	}

	scopes := strings.Split(scope, " ")
	for _, sc := range scopes {
		if sc == "" {
			return errors.BadRequest(errors.ErrMsgInvalidScopeFormat)
		}
		// Scope names should contain only alphanumeric characters, underscores, and hyphens
		for _, char := range sc {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '_' || char == '-') {
				return errors.BadRequest(errors.ErrMsgInvalidScopeFormat)
			}
		}
	}
	return nil
}

// FindScopeByName retrieves a specific scope by its name.
// Returns an error if the scope doesn't exist.
func (s *Service) FindScopeByName(ctx context.Context, name string) (*Scope, error) {
	if name == "" {
		return nil, errors.BadRequest(errors.ErrMsgInvalidScopeFormat)
	}

	scope, err := s.repo.FindByName(ctx, name)
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToFindScopeByName)
	}
	if scope == nil {
		return nil, errors.NotFound(errors.ErrMsgScopeNotFound)
	}
	return scope, nil
}
