package main

import (
	"context"
	"fmt"
	"log"

	"github.com/taqiudeen275/go-foward/internal/sms"
)

func main() {
	// Example Arkesel configuration (use your own API key)
	apiKey := "your-arkesel-api-key"
	sender := "YourApp" // Max 11 characters for Arkesel

	// Create Arkesel provider
	arkeselProvider := sms.NewArkeselProvider(apiKey, sender)

	// Create SMS service
	smsService := sms.NewService(arkeselProvider, "Go Forward Framework")

	ctx := context.Background()

	// Example 1: Send OTP SMS
	fmt.Println("Sending OTP SMS...")
	err := smsService.SendOTP(ctx, "+233123456789", "123456", "Go Forward")
	if err != nil {
		log.Printf("Failed to send OTP SMS: %v", err)
	} else {
		fmt.Println("OTP SMS sent successfully!")
	}

	// Example 2: Send custom message
	fmt.Println("Sending custom SMS...")
	err = smsService.SendMessage(ctx, "+233123456789", "Welcome to Go Forward Framework!")
	if err != nil {
		log.Printf("Failed to send SMS: %v", err)
	} else {
		fmt.Println("SMS sent successfully!")
	}

	// Example 3: Check account balance
	fmt.Println("Checking account balance...")
	balance, err := smsService.GetBalance(ctx)
	if err != nil {
		log.Printf("Failed to get balance: %v", err)
	} else {
		fmt.Printf("Account balance: %.2f %s (%s)\n", balance.Balance, balance.Currency, balance.Units)
	}

	// Example 4: Format phone numbers
	phoneNumbers := []string{
		"0123456789",
		"233123456789",
		"+233123456789",
		"(233) 123-456-789",
	}

	fmt.Println("\nPhone number formatting examples:")
	for _, phone := range phoneNumbers {
		formatted := smsService.FormatPhoneNumber(phone)
		fmt.Printf("Original: %s -> Formatted: %s\n", phone, formatted)
	}
}
