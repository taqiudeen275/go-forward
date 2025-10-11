package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const baseURL = "http://localhost:8080"

// User registration request
type RegisterRequest struct {
	Email    *string `json:"email,omitempty"`
	Username *string `json:"username,omitempty"`
	Password string  `json:"password"`
}

// User login request
type LoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// Password reset request
type PasswordResetRequest struct {
	Identifier string `json:"identifier"`
}

// Password reset confirmation request
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// Auth response
type AuthResponse struct {
	User struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Username string `json:"username"`
	} `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func main() {
	fmt.Println("Go Forward Authentication Example")
	fmt.Println("=================================")

	// Wait for server to start
	fmt.Println("Waiting for server to start...")
	time.Sleep(2 * time.Second)

	// Test user registration
	fmt.Println("\n1. Testing User Registration")
	email := "test@example.com"
	username := "testuser"
	password := "TestPassword123!"

	registerReq := RegisterRequest{
		Email:    &email,
		Username: &username,
		Password: password,
	}

	authResp, err := registerUser(registerReq)
	if err != nil {
		log.Printf("Registration failed: %v", err)
	} else {
		fmt.Printf("✓ User registered successfully: %s\n", authResp.User.Email)
		fmt.Printf("  Access Token: %s...\n", authResp.AccessToken[:20])
	}

	// Test user login
	fmt.Println("\n2. Testing User Login")
	loginReq := LoginRequest{
		Identifier: email,
		Password:   password,
	}

	authResp, err = loginUser(loginReq)
	if err != nil {
		log.Printf("Login failed: %v", err)
	} else {
		fmt.Printf("✓ User logged in successfully: %s\n", authResp.User.Email)
		fmt.Printf("  Access Token: %s...\n", authResp.AccessToken[:20])
	}

	// Test login with username
	fmt.Println("\n3. Testing Login with Username")
	loginReq = LoginRequest{
		Identifier: username,
		Password:   password,
	}

	authResp, err = loginUser(loginReq)
	if err != nil {
		log.Printf("Username login failed: %v", err)
	} else {
		fmt.Printf("✓ User logged in with username: %s\n", authResp.User.Username)
	}

	// Test password reset request
	fmt.Println("\n4. Testing Password Reset Request")
	resetReq := PasswordResetRequest{
		Identifier: email,
	}

	err = requestPasswordReset(resetReq)
	if err != nil {
		log.Printf("Password reset request failed: %v", err)
	} else {
		fmt.Println("✓ Password reset request sent successfully")
		fmt.Println("  (Check server logs for reset token)")
	}

	// Test token refresh
	fmt.Println("\n5. Testing Token Refresh")
	if authResp != nil {
		newAuthResp, err := refreshToken(authResp.RefreshToken)
		if err != nil {
			log.Printf("Token refresh failed: %v", err)
		} else {
			fmt.Printf("✓ Token refreshed successfully\n")
			fmt.Printf("  New Access Token: %s...\n", newAuthResp.AccessToken[:20])
		}
	}

	fmt.Println("\n✓ Authentication example completed!")
}

func registerUser(req RegisterRequest) (*AuthResponse, error) {
	return makeAuthRequest("POST", "/auth/register", req)
}

func loginUser(req LoginRequest) (*AuthResponse, error) {
	return makeAuthRequest("POST", "/auth/login", req)
}

func requestPasswordReset(req PasswordResetRequest) error {
	_, err := makeRequest("POST", "/auth/password-reset", req)
	return err
}

func refreshToken(refreshToken string) (*AuthResponse, error) {
	req := map[string]string{"refresh_token": refreshToken}
	return makeAuthRequest("POST", "/auth/refresh", req)
}

func makeAuthRequest(method, endpoint string, body interface{}) (*AuthResponse, error) {
	respBody, err := makeRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}

	var authResp AuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse auth response: %w", err)
	}

	return &authResp, nil
}

func makeRequest(method, endpoint string, body interface{}) ([]byte, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest(method, baseURL+endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
