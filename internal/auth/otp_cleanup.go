package auth

import (
	"context"
	"time"

	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// OTPCleanupService handles periodic cleanup of expired OTPs
type OTPCleanupService struct {
	repo   Repository
	logger *logger.Logger
	ticker *time.Ticker
	done   chan bool
}

// NewOTPCleanupService creates a new OTP cleanup service
func NewOTPCleanupService(repo Repository) *OTPCleanupService {
	return &OTPCleanupService{
		repo:   repo,
		logger: logger.GetLogger(),
		done:   make(chan bool),
	}
}

// Start begins the periodic cleanup process
func (s *OTPCleanupService) Start(interval time.Duration) {
	s.ticker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.cleanupExpiredOTPs()
			case <-s.done:
				return
			}
		}
	}()

	s.logger.Info("OTP cleanup service started", "interval", interval)
}

// Stop stops the cleanup service
func (s *OTPCleanupService) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.done <- true
	s.logger.Info("OTP cleanup service stopped")
}

// cleanupExpiredOTPs removes expired OTP codes from the database
func (s *OTPCleanupService) cleanupExpiredOTPs() {
	ctx := context.Background()

	start := time.Now()
	err := s.repo.CleanExpiredOTPs(ctx)
	duration := time.Since(start)

	if err != nil {
		s.logger.Error("Failed to clean expired OTPs", "error", err, "duration", duration)
		return
	}

	s.logger.Debug("Cleaned expired OTPs", "duration", duration)
}

// CleanupNow performs an immediate cleanup of expired OTPs
func (s *OTPCleanupService) CleanupNow() error {
	ctx := context.Background()
	return s.repo.CleanExpiredOTPs(ctx)
}
