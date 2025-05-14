package user

import "time"

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	FullName string `json:"full_name"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UpdateUserRequest struct {
	FullName          string `json:"full_name"`
	ProfilePictureURL string `json:"profile_picture_url"`
	PhoneNumber       string `json:"phone_number"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type UserResponse struct {
	ID                uint       `json:"id"`
	Username          string     `json:"username"`
	Email             string     `json:"email"`
	FullName          *string    `json:"full_name,omitempty"`
	ProfilePictureURL *string    `json:"profile_picture_url,omitempty"`
	PhoneNumber       *string    `json:"phone_number,omitempty"`
	IsActive          bool       `json:"is_active"`
	IsVerified        bool       `json:"is_verified"`
	CreatedAt         time.Time  `json:"created_at"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
}

// LoginResponse is returned after a successful login.
type LoginResponse struct {
	User         UserResponse `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresAt    time.Time    `json:"expires_at"`
}

// RefreshTokenRequest is the structure for token refresh requests.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshTokenResponse is returned after a successful token refresh.
type RefreshTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}
