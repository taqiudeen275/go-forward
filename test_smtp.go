package main

import (
	"context"
	"fmt"
	"log"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/email"
)

func main() {
	fmt.Println("=== SMTP Connection Test ===")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	fmt.Printf("SMTP Configuration:\n")
	fmt.Printf("  Host: %s\n", cfg.Auth.SMTP.Host)
	fmt.Printf("  Port: %d\n", cfg.Auth.SMTP.Port)
	fmt.Printf("  Username: %s\n", cfg.Auth.SMTP.Username)
	fmt.Printf("  From: %s\n", cfg.Auth.SMTP.From)
	fmt.Printf("  UseTLS: %t\n", cfg.Auth.SMTP.UseTLS)
	fmt.Printf("  Password: %s\n", maskPassword(cfg.Auth.SMTP.Password))

	// Test SMTP connection
	fmt.Println("\nTesting SMTP connection...")

	smtpConfig := email.SMTPConfig{
		Host:     cfg.Auth.SMTP.Host,
		Port:     cfg.Auth.SMTP.Port,
		Username: cfg.Auth.SMTP.Username,
		Password: cfg.Auth.SMTP.Password,
		From:     cfg.Auth.SMTP.From,
		UseTLS:   cfg.Auth.SMTP.UseTLS,
	}

	smtpProvider := email.NewSMTPProvider(smtpConfig)
	emailService := email.NewService(smtpProvider, "Go Forward Test")

	// Test sending a simple email
	ctx := context.Background()
	testEmail := cfg.Auth.SMTP.From // Send to self for testing

	fmt.Printf("Sending test email to: %s\n", testEmail)

	err = emailService.SendOTP(ctx, testEmail, "123456", "Go Forward Test")
	if err != nil {
		fmt.Printf("❌ SMTP Test Failed: %v\n", err)

		// Provide troubleshooting suggestions
		fmt.Println("\n🔧 Troubleshooting Suggestions:")
		fmt.Println("1. Check if 2-Factor Authentication is enabled on Gmail")
		fmt.Println("2. Verify you're using an App Password (not your regular password)")
		fmt.Println("3. Check if 'Less secure app access' is enabled (if not using App Password)")
		fmt.Println("4. Verify the email address and password are correct")
		fmt.Println("5. Check your internet connection")
		fmt.Println("6. Try using port 465 with SSL instead of 587 with TLS")

		return
	}

	fmt.Println("✅ SMTP Test Successful! Email sent.")
	fmt.Println("Check your inbox for the test OTP email.")
}

func maskPassword(password string) string {
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + "****" + password[len(password)-2:]
}
