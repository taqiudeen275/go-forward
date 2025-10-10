package dashboard

import (
	"github.com/gin-gonic/gin"
)

// ExampleIntegration shows how to integrate the dashboard into your application
func ExampleIntegration() {
	// Create Gin router
	router := gin.Default()

	// Basic setup without authentication
	config := DefaultConfig()
	Setup(router, config)

	// Or setup with authentication middleware
	// authMiddleware := func(c *gin.Context) {
	//     // Your authentication logic here
	//     // Check for valid admin session, JWT token, etc.
	//     c.Next()
	// }
	// SetupWithAuth(router, config, authMiddleware)

	// Start server
	// router.Run(":8080")

	// Dashboard will be available at:
	// http://localhost:8080/_
}

// ExampleWithCustomConfig shows configuration options
func ExampleWithCustomConfig() {
	router := gin.Default()

	// Custom configuration
	config := Config{
		Enabled:  true,
		BasePath: "/dashboard", // Custom base path
		DevMode:  false,
		DevURL:   "http://localhost:5173",
	}

	Setup(router, config)

	// Dashboard will be available at:
	// http://localhost:8080/dashboard
}
