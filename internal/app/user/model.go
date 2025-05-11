package user

import (
	"time"
)

type User struct {
	ID                      uint       `json:"id"`
	Username                string     `json:"username"`
	Email                   string     `json:"email"`
	PasswordHash            string     `json:"-"`
	FullName                *string    `json:"full_name,omitempty"`
	ProfilePictureURL       *string    `json:"profile_picture_url,omitempty"`
	PhoneNumber             *string    `json:"phone_number,omitempty"`
	IsActive                bool       `json:"is_active"`
	IsVerified              bool       `json:"is_verified"`
	VerificationToken       *string    `json:"-"`
	VerificationTokenExpiry *time.Time `json:"-"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
	LastLoginAt             *time.Time `json:"last_login_at,omitempty"`
}
