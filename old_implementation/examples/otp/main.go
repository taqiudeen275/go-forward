package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/internal/email"
	"github.com/taqiudeen275/go-foward/internal/sms"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	dbConfig := &database.Config{
		Host:            cfg.Database.Host,
		Port:            cfg.Database.Port,
		Name:            cfg.Database.Name,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		SSLMode:         cfg.Database.SSLMode,
		MaxConns:        int32(cfg.Database.MaxConns),
		MinConns:        5,
		MaxConnLifetime: cfg.Database.MaxLifetime,
		MaxConnIdleTime: 30 * time.Minute,
	}

	db, err := database.New(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create auth service
	authService := auth.NewServiceWithConfig(
		db,
		cfg.Auth.JWTSecret,
		cfg.Auth.JWTExpiration,
		cfg.Auth.RefreshExpiration,
	)

	// Set up email service if SMTP is configured
	if cfg.Auth.SMTP.Host != "" {
		smtpConfig := email.SMTPConfig{
			Host:     cfg.Auth.SMTP.Host,
			Port:     cfg.Auth.SMTP.Port,
			Username: cfg.Auth.SMTP.Username,
			Password: cfg.Auth.SMTP.Password,
			From:     cfg.Auth.SMTP.From,
			UseTLS:   cfg.Auth.SMTP.UseTLS,
		}
		smtpProvider := email.NewSMTPProvider(smtpConfig)
		emailService := email.NewService(smtpProvider, "Go Forward")
		authService.SetEmailService(emailService)
		fmt.Println("Email service configured")
	}

	// Set up SMS service if Arkesel is configured
	if cfg.Auth.SMS.Arkesel.ApiKey != "" {
		arkeselProvider := sms.NewArkeselProvider(
			cfg.Auth.SMS.Arkesel.ApiKey,
			cfg.Auth.SMS.Arkesel.Sender,
		)
		smsService := sms.NewService(arkeselProvider, "Go Forward")
		authService.SetSMSService(smsService)
		fmt.Println("SMS service configured")
	}

	ctx := context.Background()

	// Example 1: Send Email OTP
	fmt.Println("\n=== Email OTP Example ===")
	emailOTPReq := &auth.OTPRequest{
		Type:      auth.OTPTypeEmail,
		Recipient: "user@example.com",
		Purpose:   "login",
	}

	err = authService.SendOTP(ctx, emailOTPReq)
	if err != nil {
		log.Printf("Failed to send email OTP: %v", err)
	} else {
		fmt.Println("Email OTP sent successfully!")
	}

	// Example 2: Send SMS OTP
	fmt.Println("\n=== SMS OTP Example ===")
	smsOTPReq := &auth.OTPRequest{
		Type:      auth.OTPTypeSMS,
		Recipient: "+233123456789",
		Purpose:   "login",
	}

	err = authService.SendOTP(ctx, smsOTPReq)
	if err != nil {
		log.Printf("Failed to send SMS OTP: %v", err)
	} else {
		fmt.Println("SMS OTP sent successfully!")
	}

	fmt.Println("\n=== OTP Examples Complete ===")
}
