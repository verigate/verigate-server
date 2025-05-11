package user

import (
	"context"
	"time"

	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/hash"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Register(ctx context.Context, req RegisterRequest) (*UserResponse, error) {
	// Check if email already exists
	existingUser, err := s.repo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.BadRequest("Email already registered")
	}

	// Check if username already exists
	existingUser, err = s.repo.FindByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.BadRequest("Username already taken")
	}

	// Hash password
	hashedPassword, err := hash.HashPassword(req.Password)
	if err != nil {
		return nil, errors.Internal("Failed to hash password")
	}

	// Create user
	user := &User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		FullName:     &req.FullName,
		IsActive:     true,
		IsVerified:   false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.repo.Save(ctx, user); err != nil {
		return nil, err
	}

	return s.toResponse(user), nil
}

func (s *Service) Login(ctx context.Context, req LoginRequest) (*UserResponse, error) {
	user, err := s.repo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.Unauthorized("Invalid credentials")
	}

	// Verify password
	if err := hash.CompareHashAndPassword(user.PasswordHash, req.Password); err != nil {
		return nil, errors.Unauthorized("Invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.Unauthorized("Account is not active")
	}

	// Update last login
	if err := s.repo.UpdateLastLogin(ctx, user.ID); err != nil {
		// Not critical, continue
	}

	return s.toResponse(user), nil
}

func (s *Service) GetByID(ctx context.Context, id uint) (*UserResponse, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.NotFound("User not found")
	}

	return s.toResponse(user), nil
}

func (s *Service) Update(ctx context.Context, id uint, req UpdateUserRequest) error {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.NotFound("User not found")
	}

	// Update fields
	if req.FullName != "" {
		user.FullName = &req.FullName
	}
	if req.ProfilePictureURL != "" {
		user.ProfilePictureURL = &req.ProfilePictureURL
	}
	if req.PhoneNumber != "" {
		user.PhoneNumber = &req.PhoneNumber
	}
	user.UpdatedAt = time.Now()

	return s.repo.Update(ctx, user)
}

func (s *Service) ChangePassword(ctx context.Context, id uint, req ChangePasswordRequest) error {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.NotFound("User not found")
	}

	// Verify old password
	if err := hash.CompareHashAndPassword(user.PasswordHash, req.OldPassword); err != nil {
		return errors.Unauthorized("Incorrect password")
	}

	// Hash new password
	hashedPassword, err := hash.HashPassword(req.NewPassword)
	if err != nil {
		return errors.Internal("Failed to hash password")
	}

	return s.repo.UpdatePassword(ctx, id, hashedPassword)
}

func (s *Service) Delete(ctx context.Context, id uint) error {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.NotFound("User not found")
	}

	return s.repo.Delete(ctx, id)
}

func (s *Service) toResponse(user *User) *UserResponse {
	return &UserResponse{
		ID:                user.ID,
		Username:          user.Username,
		Email:             user.Email,
		FullName:          user.FullName,
		ProfilePictureURL: user.ProfilePictureURL,
		PhoneNumber:       user.PhoneNumber,
		IsActive:          user.IsActive,
		IsVerified:        user.IsVerified,
		CreatedAt:         user.CreatedAt,
		LastLoginAt:       user.LastLoginAt,
	}
}
