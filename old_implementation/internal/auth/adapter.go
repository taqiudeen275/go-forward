package auth

import (
	"context"

	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// ServiceAdapter adapts the auth service to implement interfaces.AuthService
type ServiceAdapter struct {
	service *Service
}

// NewServiceAdapter creates a new auth service adapter
func NewServiceAdapter(service *Service) *ServiceAdapter {
	return &ServiceAdapter{
		service: service,
	}
}

// Register implements interfaces.AuthService
func (a *ServiceAdapter) Register(ctx context.Context, req interfaces.RegisterRequest) (*interfaces.User, error) {
	// Convert interface request to internal request
	var email, phone, username *string
	if req.Email != "" {
		email = &req.Email
	}
	if req.Phone != "" {
		phone = &req.Phone
	}
	if req.Username != "" {
		username = &req.Username
	}

	internalReq := &CreateUserRequest{
		Email:    email,
		Phone:    phone,
		Username: username,
		Password: req.Password,
		Metadata: req.Metadata,
	}

	response, err := a.service.Register(ctx, internalReq)
	if err != nil {
		return nil, err
	}

	// Convert internal user to interface user
	interfaceUser := &interfaces.User{
		ID:            response.User.ID,
		Email:         getStringValue(response.User.Email),
		Phone:         getStringValue(response.User.Phone),
		Username:      getStringValue(response.User.Username),
		EmailVerified: response.User.EmailVerified,
		PhoneVerified: response.User.PhoneVerified,
		Metadata:      response.User.Metadata,
		CreatedAt:     response.User.CreatedAt,
		UpdatedAt:     response.User.UpdatedAt,
	}

	return interfaceUser, nil
}

// Login implements interfaces.AuthService
func (a *ServiceAdapter) Login(ctx context.Context, req interfaces.LoginRequest) (*interfaces.AuthResponse, error) {
	// Convert interface request to internal request
	internalReq := &LoginRequest{
		Identifier: req.Identifier,
		Password:   req.Password,
	}

	response, err := a.service.Login(ctx, internalReq)
	if err != nil {
		return nil, err
	}

	// Convert internal response to interface response
	interfaceResponse := &interfaces.AuthResponse{
		User: &interfaces.User{
			ID:            response.User.ID,
			Email:         getStringValue(response.User.Email),
			Phone:         getStringValue(response.User.Phone),
			Username:      getStringValue(response.User.Username),
			EmailVerified: response.User.EmailVerified,
			PhoneVerified: response.User.PhoneVerified,
			Metadata:      response.User.Metadata,
			CreatedAt:     response.User.CreatedAt,
			UpdatedAt:     response.User.UpdatedAt,
		},
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		ExpiresIn:    response.ExpiresIn,
	}

	return interfaceResponse, nil
}

// SendOTP implements interfaces.AuthService
func (a *ServiceAdapter) SendOTP(ctx context.Context, req interfaces.OTPRequest) error {
	// Convert string type to OTPType
	var otpType OTPType
	switch req.Type {
	case "email":
		otpType = OTPTypeEmail
	case "sms":
		otpType = OTPTypeSMS
	default:
		otpType = OTPTypeEmail // default
	}

	// Convert interface request to internal request
	internalReq := &OTPRequest{
		Type:      otpType,
		Recipient: req.Identifier,
		Purpose:   OTPPurposeLogin, // default purpose
	}

	return a.service.SendOTP(ctx, internalReq)
}

// VerifyOTP implements interfaces.AuthService
func (a *ServiceAdapter) VerifyOTP(ctx context.Context, req interfaces.VerifyOTPRequest) (*interfaces.AuthResponse, error) {
	// Convert string type to OTPType
	var otpType OTPType
	switch req.Type {
	case "email":
		otpType = OTPTypeEmail
	case "sms":
		otpType = OTPTypeSMS
	default:
		otpType = OTPTypeEmail // default
	}

	// Convert interface request to internal request
	internalReq := &VerifyOTPRequest{
		Type:      otpType,
		Recipient: req.Identifier,
		Code:      req.Code,
	}

	// Use LoginWithOTP for verification
	response, err := a.service.LoginWithOTP(ctx, internalReq)
	if err != nil {
		return nil, err
	}

	// Convert internal response to interface response
	interfaceResponse := &interfaces.AuthResponse{
		User: &interfaces.User{
			ID:            response.User.ID,
			Email:         getStringValue(response.User.Email),
			Phone:         getStringValue(response.User.Phone),
			Username:      getStringValue(response.User.Username),
			EmailVerified: response.User.EmailVerified,
			PhoneVerified: response.User.PhoneVerified,
			Metadata:      response.User.Metadata,
			CreatedAt:     response.User.CreatedAt,
			UpdatedAt:     response.User.UpdatedAt,
		},
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		ExpiresIn:    response.ExpiresIn,
	}

	return interfaceResponse, nil
}

// ValidateToken implements interfaces.AuthService
func (a *ServiceAdapter) ValidateToken(ctx context.Context, token string) (*interfaces.Claims, error) {
	claims, err := a.service.jwtManager.ValidateAccessToken(token)
	if err != nil {
		return nil, err
	}

	// Convert internal claims to interface claims
	interfaceClaims := &interfaces.Claims{
		UserID:    claims.UserID,
		Email:     claims.Email,
		Metadata:  claims.Metadata,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	return interfaceClaims, nil
}

// RefreshToken implements interfaces.AuthService
func (a *ServiceAdapter) RefreshToken(ctx context.Context, refreshToken string) (*interfaces.AuthResponse, error) {
	response, err := a.service.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Convert internal response to interface response
	interfaceResponse := &interfaces.AuthResponse{
		User: &interfaces.User{
			ID:            response.User.ID,
			Email:         getStringValue(response.User.Email),
			Phone:         getStringValue(response.User.Phone),
			Username:      getStringValue(response.User.Username),
			EmailVerified: response.User.EmailVerified,
			PhoneVerified: response.User.PhoneVerified,
			Metadata:      response.User.Metadata,
			CreatedAt:     response.User.CreatedAt,
			UpdatedAt:     response.User.UpdatedAt,
		},
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		ExpiresIn:    response.ExpiresIn,
	}

	return interfaceResponse, nil
}

// Logout implements interfaces.AuthService
func (a *ServiceAdapter) Logout(ctx context.Context, token string) error {
	// The interface only provides one token, so we'll use it as the access token
	// and pass empty string for refresh token
	return a.service.Logout(ctx, token, "")
}

// Helper function to safely get string value from pointer
func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
