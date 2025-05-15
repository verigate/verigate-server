# Verigate Server

<div align="center">
  
  [![Go Report Card](https://goreportcard.com/badge/github.com/verigate/verigate-server)](https://goreportcard.com/report/github.com/verigate/verigate-server)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Go version](https://img.shields.io/github/go-mod/go-version/verigate/verigate-server)](https://github.com/verigate/verigate-server)
  
</div>

## Overview

Verigate Server is a robust, secure, and standards-compliant OAuth 2.0 and OpenID Connect provider built with Go. It offers comprehensive authentication and authorization services for modern applications, including secure token management, user identity verification, and client application registration.

## Features

- **Complete OAuth 2.0 Implementation**

  - Authorization Code Flow with PKCE
  - Refresh Token Flow
  - Token Revocation (RFC 7009)

- **OpenID Connect Support**

  - Standard Claims
  - UserInfo Endpoint

- **Advanced Security Features**

  - JSON Web Tokens (JWT) with RSA Signing
  - Rate Limiting
  - IP Access Control
  - PKCE for Public Clients

- **Comprehensive Client Management**

  - Client Registration and Configuration
  - Scope-based Permissions
  - User Consent Management

- **Scalable Architecture**
  - PostgreSQL for Persistence
  - Redis for Caching and Rate Limiting
  - Docker Support

## Getting Started

### Prerequisites

- Go 1.18 or higher
- PostgreSQL 13 or higher
- Redis 6 or higher
- Docker and Docker Compose (optional)

### Installation

#### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/verigate/verigate-server.git
cd verigate-server

# Start with Docker Compose
docker-compose up -d
```

#### Manual Setup

```bash
# Clone the repository
git clone https://github.com/verigate/verigate-server.git
cd verigate-server

# Install dependencies
go mod download

# Set up environment variables (see .env.example)
cp .env.example .env
# Edit .env with your configuration

# Build the application
go build -o verigate-server ./cmd/api

# Run the server
./verigate-server
```

### Configuration

Verigate Server can be configured via environment variables or a configuration file. See the example in `.env.example` for all available options.

Key configuration parameters:

```
# Server settings
APP_PORT=8080
APP_ENV=development

# Database settings
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=verigate

# Redis settings
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# JWT settings (use proper keys in production)
JWT_PRIVATE_KEY=...
JWT_PUBLIC_KEY=...
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d
```

## API Documentation

### OAuth 2.0 Endpoints

- `POST /oauth/token` - Token issuance endpoint
- `POST /oauth/revoke` - Token revocation endpoint
- `GET /oauth/authorize` - Authorization endpoint
- `GET /oauth/userinfo` - UserInfo endpoint
- `GET /oauth/consent` - User consent page
- `POST /oauth/consent` - User consent submission

### Client Management Endpoints

- `POST /clients` - Register a new client
- `GET /clients` - List registered clients
- `GET /clients/:id` - Get client details
- `PUT /clients/:id` - Update client
- `DELETE /clients/:id` - Delete client

### User Management Endpoints

- `POST /users/register` - Register a new user
- `POST /users/login` - Authenticate user
- `GET /users/me` - Get authenticated user profile
- `PUT /users/me` - Update user profile
- `PUT /users/me/password` - Change password
- `DELETE /users/me` - Delete user account
- `POST /users/logout` - Log out (revoke all tokens)
- `POST /users/refresh-token` - Refresh access token

## Architecture

Verigate Server follows a clean architecture pattern with distinct layers:

- **API Layer** - HTTP handlers and middleware
- **Service Layer** - Business logic and workflows
- **Repository Layer** - Data access and persistence
- **Domain Layer** - Core business models and rules

## Security

Verigate Server implements security best practices including:

- Secure password hashing with bcrypt
- JWT tokens with RSA signatures
- Protection against common OAuth vulnerabilities
- Rate limiting to prevent abuse
- IP-based access control

## Development

### Project Structure

```
cmd/                # Application entry points
  └── api/          # API server executable
internal/           # Private application code
  ├── app/          # Domain-specific packages (business logic)
  └── pkg/          # Shared utilities and infrastructure
migrations/         # Database migrations
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/app/oauth
```

## Contributing

We welcome contributions to Verigate Server! Please see our [Contributing Guide](CONTRIBUTING.md) for details on how to get involved.

## License

Verigate Server is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [OAuth 2.0 Framework](https://oauth.net/2/)
- [OpenID Connect](https://openid.net/connect/)
- [Go Programming Language](https://golang.org/)
- [Gin Web Framework](https://gin-gonic.com/)
