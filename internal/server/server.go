package server

import (
	"github.com/taqiudeen275/go-foward/internal/api"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/internal/email"
	"github.com/taqiudeen275/go-foward/internal/gateway"
	"github.com/taqiudeen275/go-foward/internal/gateway/middleware"
	"github.com/taqiudeen275/go-foward/internal/realtime"
	"github.com/taqiudeen275/go-foward/internal/sms"
	"github.com/taqiudeen275/go-foward/internal/storage"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

type Server struct {
	config           *config.Config
	logger           logger.Logger
	db               *database.DB
	gateway          *gateway.Gateway
	authService      *auth.Service
	authHandler      *auth.Handler
	apiService       *api.Service
	realtimeService  *realtime.Service
	realtimeHandlers *realtime.Handlers
	storageService   *storage.Service
	storageHandlers  *storage.Handlers
	metaService      *database.MetaService
	databaseHandlers *database.Handlers
}

func New(cfg *config.Config, db *database.DB) *Server {
	// Initialize logger
	log := logger.New(cfg.Server.LogLevel)

	// Initialize gateway
	gw := gateway.New(cfg, log)

	// Initialize database meta service
	metaService := database.NewMetaService(db)
	databaseHandlers := database.NewHandlers(metaService)

	// Initialize auth service with configuration
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
		log.Info("Email service configured for OTP delivery")
	}

	// Set up SMS service if Arkesel is configured
	if cfg.Auth.SMS.Arkesel.ApiKey != "" {
		arkeselProvider := sms.NewArkeselProvider(
			cfg.Auth.SMS.Arkesel.ApiKey,
			cfg.Auth.SMS.Arkesel.Sender,
		)
		smsService := sms.NewService(arkeselProvider, "Go Forward")
		authService.SetSMSService(smsService)
		log.Info("SMS service configured for OTP delivery")
	}

	authHandler := auth.NewHandler(authService)

	// Initialize API service with adapter
	metaServiceAdapter := database.NewMetaServiceAdapter(metaService)
	apiService := api.NewService(metaServiceAdapter)

	// Create auth service adapter for realtime service
	authServiceAdapter := auth.NewServiceAdapter(authService)

	// Initialize realtime service with auth service adapter
	realtimeService := realtime.NewService(authServiceAdapter, db.Pool)
	realtimeHandlers := realtime.NewHandlers(realtimeService)

	// Initialize storage service
	storageService := storage.NewService(db, cfg.Storage.LocalPath)
	accessControl := storage.NewAccessControlService(db)
	storageHandlers := storage.NewHandlers(storageService, accessControl)

	return &Server{
		config:           cfg,
		logger:           log,
		db:               db,
		gateway:          gw,
		authService:      authService,
		authHandler:      authHandler,
		apiService:       apiService,
		realtimeService:  realtimeService,
		realtimeHandlers: realtimeHandlers,
		storageService:   storageService,
		storageHandlers:  storageHandlers,
		metaService:      metaService,
		databaseHandlers: databaseHandlers,
	}
}

func (s *Server) Start() error {
	// Setup middleware
	s.setupMiddleware()

	// Register services
	s.registerServices()

	// Start the gateway
	return s.gateway.Start()
}

func (s *Server) setupMiddleware() {
	// Add CORS middleware
	s.gateway.AddMiddleware(middleware.CORS(s.config.Server.CORS))

	// Add rate limiting middleware
	s.gateway.AddMiddleware(middleware.RateLimit(s.config.Server.RateLimit))

	// Add monitoring middleware
	s.gateway.AddMiddleware(middleware.MonitoringMiddleware(s.logger))

	// Add security headers middleware
	s.gateway.AddMiddleware(middleware.SecurityHeadersMiddleware())

	// Add request ID middleware
	s.gateway.AddMiddleware(middleware.RequestIDMiddleware())
}

func (s *Server) registerServices() {
	// Register authentication service
	if err := s.gateway.RegisterService(s.authHandler); err != nil {
		s.logger.Error("Failed to register auth service: %v", err)
	}

	// Register API service
	if err := s.gateway.RegisterService(s.apiService); err != nil {
		s.logger.Error("Failed to register API service: %v", err)
	}

	// Register realtime service
	if err := s.gateway.RegisterService(s.realtimeHandlers); err != nil {
		s.logger.Error("Failed to register realtime service: %v", err)
	}

	// Register storage service
	if err := s.gateway.RegisterService(s.storageHandlers); err != nil {
		s.logger.Error("Failed to register storage service: %v", err)
	}

	// Register database meta service
	if err := s.gateway.RegisterService(s.databaseHandlers); err != nil {
		s.logger.Error("Failed to register database service: %v", err)
	}

	s.logger.Info("All services registered successfully")
}
