@echo off
REM Build script for Unified Go Forward Framework (Windows)

echo 🏗️  Building Unified Go Forward Framework...

REM Check if pnpm is installed
pnpm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pnpm is required but not installed. Please install pnpm first.
    exit /b 1
)

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Go is required but not installed. Please install Go 1.25.1 or later.
    exit /b 1
)

REM Build dashboard
echo [INFO] Building SvelteKit dashboard...
cd dashboard

REM Install dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo [INFO] Installing dashboard dependencies...
    pnpm install
)

REM Build dashboard
echo [INFO] Compiling dashboard...
pnpm build

cd ..

REM Build Go application
echo [INFO] Building Go application...

REM Ensure go.mod is tidy
go mod tidy

REM Run tests
echo [INFO] Running tests...
go test ./...

REM Build binary
echo [INFO] Compiling Go binary...
set CGO_ENABLED=0
go build -ldflags="-s -w" -o go-forward.exe cmd/main.go

echo [INFO] ✅ Build completed successfully!
echo [INFO] 📦 Binary: ./go-forward.exe
echo [INFO] 🎯 Dashboard: embedded in binary (/_/ prefix)

echo.
echo Usage:
echo   go-forward.exe                    # Start server
echo   go-forward.exe admin --help       # Admin CLI commands
echo   go-forward.exe migrate --help     # Migration commands