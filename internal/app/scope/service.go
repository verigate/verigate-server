package scope

import (
	"context"
	"strings"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

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
		return false, err
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
		return nil, err
	}

	var scopeNames []string
	for _, scope := range scopes {
		scopeNames = append(scopeNames, scope.Name)
	}

	return scopeNames, nil
}

func (s *Service) GetAllScopes(ctx context.Context) ([]Scope, error) {
	return s.repo.FindAll(ctx)
}
