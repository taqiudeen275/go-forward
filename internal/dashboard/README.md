# Admin Dashboard

This package provides an embedded SvelteKit admin dashboard for the Go Forward framework with security-focused design and embedded static asset serving.

## Features

- **Embedded SvelteKit App**: Static assets are embedded in the Go binary
- **Security Headers**: Comprehensive security headers including CSP, CSRF protection
- **Mobile-First Design**: Responsive design with Tailwind CSS
- **SPA Routing**: Proper fallback handling for single-page application routing
- **Cache Optimization**: Appropriate cache headers for static assets vs. HTML
- **Development Mode**: Support for development server proxy

## Quick Start

### 1. Build the Dashboard

```bash
# On Windows
scripts\build-dashboard.bat

# On Unix/Linux/macOS
./scripts/build-dashboard.sh

# Or manually
cd web/admin-dashboard
pnpm install
pnpm run build:embedded
```

### 2. Integrate into Your Application

```go
package main

import (
    "github.com/gin-gonic/gin"
    "go-forward/internal/dashboard"
)

func main() {
    router := gin.Default()
    
    // Basic setup
    config := dashboard.DefaultConfig()
    dashboard.Setup(router, config)
    
    router.Run(":8080")
    // Dashboard available at http://localhost:8080/admin
}
```

### 3. With Authentication Middleware

```go
func main() {
    router := gin.Default()
    
    // Your authentication middleware
    authMiddleware := func(c *gin.Context) {
        // Check admin session, JWT token, etc.
        if !isValidAdminSession(c) {
            c.Redirect(302, "/admin/login")
            c.Abort()
            return
        }
        c.Next()
    }
    
    config := dashboard.DefaultConfig()
    dashboard.SetupWithAuth(router, config, authMiddleware)
    
    router.Run(":8080")
}
```

## Configuration

```go
type Config struct {
    Enabled    bool   // Enable/disable dashboard
    BasePath   string // Base URL path (default: "/admin")
    DevMode    bool   // Development mode (proxy to dev server)
    DevURL     string // Development server URL
}
```

## Security Features

- **Content Security Policy**: Strict CSP headers to prevent XSS
- **Frame Protection**: X-Frame-Options to prevent clickjacking
- **Content Type Protection**: X-Content-Type-Options to prevent MIME sniffing
- **XSS Protection**: X-XSS-Protection header
- **Referrer Policy**: Strict referrer policy
- **Permissions Policy**: Restrictive permissions for browser APIs

## Development

### Frontend Development

```bash
cd web/admin-dashboard
pnpm install
pnpm run dev
```

The development server runs on `http://localhost:5173`

### Building for Production

```bash
cd web/admin-dashboard
pnpm run build:embedded
```

This will:
1. Build the SvelteKit app with production optimizations
2. Copy assets to `internal/dashboard/embed/build/`
3. Update the Go embed file

## File Structure

```
internal/dashboard/
├── dashboard.go          # Main package and setup functions
├── service.go           # HTTP service with security middleware
├── embed/
│   ├── assets.go        # Go embed file
│   └── build/           # Built SvelteKit assets
└── README.md

web/admin-dashboard/
├── src/                 # SvelteKit source code
├── scripts/
│   └── prepare-embedded.js  # Build script for Go embedding
├── package.json
├── svelte.config.js     # SvelteKit configuration
└── vite.config.ts       # Vite configuration
```

## Customization

The dashboard is built with SvelteKit and Tailwind CSS, making it easy to customize:

1. **Styling**: Modify Tailwind configuration or add custom CSS
2. **Components**: Add new Svelte components in `src/lib/components/`
3. **Routes**: Add new pages in `src/routes/`
4. **API Integration**: Use SvelteKit's load functions and actions

## Security Considerations

- All static assets are served with appropriate cache headers
- HTML files are served with no-cache headers to ensure fresh content
- Comprehensive security headers are applied to all responses
- Path traversal protection prevents access to files outside the build directory
- Content Security Policy prevents inline scripts and external resources