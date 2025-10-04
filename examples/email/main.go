package main

import (
	"context"
	"fmt"
	"log"

	"github.com/taqiudeen275/go-foward/internal/email"
)

func main() {
	// Example SMTP configuration (use your own SMTP settings)
	smtpConfig := email.SMTPConfig{
		Host:     "smtp.gmail.com",
		Port:     587,
		Username: "your-email@gmail.com",
		Password: "your-app-password", // Use app password for Gmail
		From:     "your-email@gmail.com",
		UseTLS:   true,
	}

	// Create SMTP provider
	smtpProvider := email.NewSMTPProvider(smtpConfig)

	// Create email service
	emailService := email.NewService(smtpProvider, "Go Forward Framework")

	ctx := context.Background()

	// Example 1: Send OTP email
	fmt.Println("Sending OTP email...")
	err := emailService.SendOTP(ctx, "recipient@example.com", "123456", "Go Forward")
	if err != nil {
		log.Printf("Failed to send OTP email: %v", err)
	} else {
		fmt.Println("OTP email sent successfully!")
	}

	// Example 2: Send password reset email
	fmt.Println("Sending password reset email...")
	err = emailService.SendPasswordReset(ctx, "recipient@example.com", "reset-token-123", "Go Forward")
	if err != nil {
		log.Printf("Failed to send password reset email: %v", err)
	} else {
		fmt.Println("Password reset email sent successfully!")
	}

	// Example 3: Send welcome email
	fmt.Println("Sending welcome email...")
	err = emailService.SendWelcome(ctx, "recipient@example.com", "John Doe", "Go Forward")
	if err != nil {
		log.Printf("Failed to send welcome email: %v", err)
	} else {
		fmt.Println("Welcome email sent successfully!")
	}
}
