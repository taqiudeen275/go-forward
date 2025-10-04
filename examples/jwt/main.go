package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/internal/database"
)

func main() {
	// Create database configuration
	config := &database.Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     5432,
		Name:     getEnv("DB_NAME", "postgres"),
		User:     getEnv("DB_USER", "postgres"),
		Password: getEnv("DB_PASSWORD", "postgres"),
		SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		MaxConns: 25,
		MinConns: 5,
	}

	// Create database service
	dbService, err := database.NewService(config)
	if err != nil {
		log.Fatalf("Failed to create database service: %v", err)
	}
	defer dbService.Close()

	ctx := context.Background()

	// Initialize database
	fmt.Println("Initializing database...")
	if err := dbService.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	fmt.Println("Database initialized successfully!")

	// Create auth service with JWT configuration
	jwtSecret := getEnv("JWT_SECRET", "my-super-secret-jwt-key-for-testing")
	authService := auth.NewServiceWithConfig(
		dbService.DB,
		jwtSecret,
		15*time.Minute, // Access token expires in 15 minutes
		7*24*time.Hour, // Refresh token expires in 7 days
	)

	// Example 1: Register a new user and get tokens
	fmt.Println("\n=== User Registration with JWT ===")
	email := "jwt.user@example.com"
	registerReq := &auth.CreateUserRequest{
		Email:    &email,
		Password: "SecurePass123!",
		Metadata: map[string]interface{}{
			"role": "user",
		},
	}

	authResponse, err := authService.Register(ctx, registerReq)
	if err != nil {
		log.Printf("Failed to register user: %v", err)
	} else {
		fmt.Printf("User registered successfully!\n")
		fmt.Printf("User ID: %s\n", authResponse.User.ID)
		fmt.Printf("Access Token: %s...\n", authResponse.AccessToken[:50])
		fmt.Printf("Refresh Token: %s...\n", authResponse.RefreshToken[:50])
		fmt.Printf("Expires In: %d seconds\n", authResponse.ExpiresIn)
	}

	// Example 2: Login with existing user
	fmt.Println("\n=== User Login with JWT ===")
	loginReq := &auth.LoginRequest{
		Identifier: email,
		Password:   "SecurePass123!",
	}

	loginResponse, err := authService.Login(ctx, loginReq)
	if err != nil {
		log.Printf("Failed to login: %v", err)
	} else {
		fmt.Printf("Login successful!\n")
		fmt.Printf("Access Token: %s...\n", loginResponse.AccessToken[:50])
		fmt.Printf("Refresh Token: %s...\n", loginResponse.RefreshToken[:50])
	}

	// Example 3: Validate access token
	if loginResponse != nil {
		fmt.Println("\n=== Token Validation ===")
		claims, err := authService.ValidateToken(ctx, loginResponse.AccessToken)
		if err != nil {
			log.Printf("Token validation failed: %v", err)
		} else {
			fmt.Printf("Token is valid!\n")
			fmt.Printf("User ID: %s\n", claims.UserID)
			fmt.Printf("Email: %s\n", claims.Email)
			fmt.Printf("Token Type: %s\n", claims.TokenType)
			fmt.Printf("Expires At: %s\n", claims.ExpiresAt.Time.Format(time.RFC3339))
		}
	}

	// Example 4: Refresh tokens
	if loginResponse != nil {
		fmt.Println("\n=== Token Refresh ===")
		refreshResponse, err := authService.RefreshToken(ctx, loginResponse.RefreshToken)
		if err != nil {
			log.Printf("Token refresh failed: %v", err)
		} else {
			fmt.Printf("Tokens refreshed successfully!\n")
			fmt.Printf("New Access Token: %s...\n", refreshResponse.AccessToken[:50])
			fmt.Printf("New Refresh Token: %s...\n", refreshResponse.RefreshToken[:50])
		}
	}

	// Example 5: Create a simple HTTP server with JWT middleware
	fmt.Println("\n=== Starting HTTP Server with JWT Middleware ===")

	// Create Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// Create middleware
	middleware := authService.CreateMiddleware()

	// Public routes
	router.POST("/register", func(c *gin.Context) {
		var req auth.CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		response, err := authService.Register(c.Request.Context(), &req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, response)
	})

	router.POST("/login", func(c *gin.Context) {
		var req auth.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		response, err := authService.Login(c.Request.Context(), &req)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, response)
	})

	router.POST("/refresh", func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		response, err := authService.RefreshToken(c.Request.Context(), req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, response)
	})

	// Protected routes
	protected := router.Group("/api")
	protected.Use(middleware.RequireAuth())
	{
		protected.GET("/profile", func(c *gin.Context) {
			user := middleware.GetUserFromContext(c)
			claims := middleware.GetClaimsFromContext(c)

			c.JSON(http.StatusOK, gin.H{
				"user":   user,
				"claims": claims,
			})
		})

		protected.PUT("/profile", func(c *gin.Context) {
			user := middleware.GetUserFromContext(c)

			var req auth.UpdateUserRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			updatedUser, err := authService.UpdateUser(c.Request.Context(), user.ID, &req)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, updatedUser)
		})
	}

	// Admin routes (require admin role)
	admin := router.Group("/admin")
	admin.Use(middleware.RequireAuth(), middleware.RequireRole("admin"))
	{
		admin.GET("/users", func(c *gin.Context) {
			users, err := authService.ListUsers(c.Request.Context(), &auth.UserFilter{
				Limit: 100,
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"users": users})
		})
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	fmt.Printf("Server starting on :8080\n")
	fmt.Printf("Try these endpoints:\n")
	fmt.Printf("  POST /register - Register a new user\n")
	fmt.Printf("  POST /login - Login with credentials\n")
	fmt.Printf("  POST /refresh - Refresh tokens\n")
	fmt.Printf("  GET /api/profile - Get user profile (requires auth)\n")
	fmt.Printf("  PUT /api/profile - Update user profile (requires auth)\n")
	fmt.Printf("  GET /admin/users - List users (requires admin role)\n")
	fmt.Printf("  GET /health - Health check\n")

	// Start server in a goroutine so we can demonstrate API calls
	go func() {
		if err := router.Run(":8080"); err != nil {
			log.Printf("Server failed to start: %v", err)
		}
	}()

	// Wait a moment for server to start
	time.Sleep(2 * time.Second)

	fmt.Println("\nJWT example completed successfully!")
	fmt.Println("Server is running on :8080 - press Ctrl+C to stop")

	// Keep the server running
	select {}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
