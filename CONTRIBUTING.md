# Contributing to Verigate Server

This document outlines the coding standards and best practices for the Verigate Server project. Following these guidelines will help maintain consistency across the codebase and make it easier for contributors to understand and modify the code.

## Project Architecture

The project follows a clean architecture pattern with clear separation of concerns:

```
cmd/                # Application entry points
  └── api/          # API server executable
internal/           # Private application code
  ├── app/          # Domain-specific packages (business logic)
  └── pkg/          # Shared utilities and infrastructure
migrations/         # Database migrations
```

## Package Structure

Each domain package should follow this structure:

- **model.go**: Data structures/entities
- **dto.go**: Data Transfer Objects for API requests/responses
- **repository.go**: Interface for data access
- **service.go**: Business logic
- **handler.go**: HTTP request handlers

## Code Style Guidelines

### Package Documentation

Every package should have a package comment that describes its purpose:

```go
// Package user provides functionality for managing user accounts,
// including registration, authentication, and profile management.
package user
```

### Function Documentation

Public functions and methods should have a comment that explains their purpose:

```go
// CreateUser creates a new user account with the provided information.
// It validates the input, hashes the password, and stores the new user in the database.
// Returns the created user or an error if validation fails or the user already exists.
func (s *Service) CreateUser(ctx context.Context, req CreateUserRequest) (*UserResponse, error) {
    // ...
}
```

### Error Handling

Use the custom error types defined in `internal/pkg/utils/errors` for API errors:

```go
// Good
if user == nil {
    return nil, errors.NotFound("user not found")
}

// Bad
if user == nil {
    return nil, fmt.Errorf("user not found")
}
```

### Context Usage

Always pass context through function calls for cancellation and request tracing:

```go
// Good
func (s *Service) GetUser(ctx context.Context, id uint) (*User, error) {
    return s.repo.FindByID(ctx, id)
}

// Bad
func (s *Service) GetUser(id uint) (*User, error) {
    return s.repo.FindByID(context.Background(), id)
}
```

### Struct Field Comments

Document struct fields, especially in model definitions:

```go
// User represents a registered user in the system.
type User struct {
    ID         uint       `json:"id"`          // Unique identifier
    Username   string     `json:"username"`    // Unique username
    Email      string     `json:"email"`       // Unique email address
    FullName   *string    `json:"full_name"`   // Optional full name
    IsVerified bool       `json:"is_verified"` // Whether email is verified
    CreatedAt  time.Time  `json:"created_at"`  // When the user was created
}
```

### Constants and Variables

Group related constants using const blocks and provide explanatory comments:

```go
// Authorization-related constants
const (
    accessTokenPrefix  = "access:"  // Redis key prefix for access tokens
    refreshTokenPrefix = "refresh:" // Redis key prefix for refresh tokens
    defaultTokenTTL    = 15 * time.Minute // Default TTL for access tokens
)
```

### Repository Implementations

Repository implementations should follow consistent patterns:

1. The repository struct should be private
2. Constructor function should return the interface type
3. Error wrapping should provide context

```go
// Package postgres provides PostgreSQL implementations of the application's repositories.
package postgres

// userRepository implements the user.Repository interface using PostgreSQL.
type userRepository struct {
    db *sql.DB
}

// NewUserRepository creates a new PostgreSQL-based user repository.
func NewUserRepository(db *sql.DB) user.Repository {
    return &userRepository{db: db}
}
```

## Testing Guidelines

- Every package should have unit tests
- Mock interfaces for testing services
- Integration tests for repositories
- Test coverage should be maintained at 80% or higher

## Pull Request Process

1. Make sure code follows the style guidelines in this document
2. Include relevant unit tests for new functionality
3. Update documentation if necessary
4. Rebase commits into logical units
5. Get code reviewed by at least one team member

## License

By contributing to this project, you agree that your contributions will be licensed under the project license.
