package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

type Server struct {
	config      *config.Config
	router      *gin.Engine
	logger      logger.Logger
	db          *database.DB
	authService *auth.Service
	authHandler *auth.Handler
}

func New(cfg *config.Config, db *database.DB) *Server {
	// Initialize auth service
	authService := auth.NewService(db)
	authHandler := auth.NewHandler(authService)

	return &Server{
		config:      cfg,
		router:      gin.New(),
		logger:      logger.New(cfg.Server.LogLevel),
		db:          db,
		authService: authService,
		authHandler: authHandler,
	}
}

func (s *Server) Start() error {
	// Setup middleware
	s.setupMiddleware()

	// Setup routes
	s.setupRoutes()

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port),
		Handler:      s.router,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
	}

	// Start server in a goroutine
	go func() {
		s.logger.Info("Starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	s.logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return srv.Shutdown(ctx)
}

func (s *Server) setupMiddleware() {
	s.router.Use(gin.Recovery())
	s.router.Use(s.loggingMiddleware())
}

func (s *Server) setupRoutes() {
	// Health check endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Register authentication routes
	s.authHandler.RegisterRoutes(s.router)
}

func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)

		s.logger.Info("%s %s %d %v",
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			duration,
		)
	}
}
