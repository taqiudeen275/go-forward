#!/bin/bash

# Build script for Unified Go Forward Framework
set -e

echo "🏗️  Building Unified Go Forward Framework..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if pnpm is installed
if ! command -v pnpm &> /dev/null; then
    print_error "pnpm is required but not installed. Please install pnpm first."
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is required but not installed. Please install Go 1.25.1 or later."
    exit 1
fi

# Build dashboard
print_status "Building SvelteKit dashboard..."
cd dashboard

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    print_status "Installing dashboard dependencies..."
    pnpm install
fi

# Build dashboard
print_status "Compiling dashboard..."
pnpm build

cd ..

# Build Go application
print_status "Building Go application..."

# Ensure go.mod is tidy
go mod tidy

# Run tests
print_status "Running tests..."
go test ./... || print_warning "Some tests failed, continuing with build..."

# Build binary
print_status "Compiling Go binary..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o go-forward cmd/main.go

# Make binary executable
chmod +x go-forward

print_status "✅ Build completed successfully!"
print_status "📦 Binary: ./go-forward"
print_status "🎯 Dashboard: embedded in binary (/_/ prefix)"

echo ""
echo "Usage:"
echo "  ./go-forward                    # Start server"
echo "  ./go-forward admin --help       # Admin CLI commands"
echo "  ./go-forward migrate --help     # Migration commands"