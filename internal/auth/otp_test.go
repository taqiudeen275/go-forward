package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taqiudeen275/go-foward/internal/config"
)

func TestGenerateOTPCode(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			OTPLength: 6,
		},
	}

	otpService := &otpService{
		config: cfg,
	}

	code, err := otpService.generateOTPCode()

	assert.NoError(t, err)
	assert.Len(t, code, 6)
	assert.Regexp(t, "^[0-9]{6}$", code)
}

func TestValidateOTPRequest(t *testing.T) {
	otpService := &otpService{}

	tests := []struct {
		name    string
		req     *OTPRequest
		wantErr bool
	}{
		{
			name: "valid email request",
			req: &OTPRequest{
				Identifier: "test@example.com",
				Purpose:    "login",
			},
			wantErr: false,
		},
		{
			name: "valid phone request",
			req: &OTPRequest{
				Identifier: "1234567890",
				Purpose:    "registration",
			},
			wantErr: false,
		},
		{
			name: "missing identifier",
			req: &OTPRequest{
				Purpose: "login",
			},
			wantErr: true,
		},
		{
			name: "missing purpose",
			req: &OTPRequest{
				Identifier: "test@example.com",
			},
			wantErr: true,
		},
		{
			name: "invalid purpose",
			req: &OTPRequest{
				Identifier: "test@example.com",
				Purpose:    "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := otpService.validateOTPRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyOTPCode(t *testing.T) {
	otpService := &otpService{}

	tests := []struct {
		name     string
		provided string
		stored   string
		expected bool
	}{
		{
			name:     "matching codes",
			provided: "123456",
			stored:   "123456",
			expected: true,
		},
		{
			name:     "non-matching codes",
			provided: "123456",
			stored:   "654321",
			expected: false,
		},
		{
			name:     "different lengths",
			provided: "12345",
			stored:   "123456",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := otpService.verifyOTPCode(tt.provided, tt.stored)
			assert.Equal(t, tt.expected, result)
		})
	}
}
