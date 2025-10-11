# Multi-stage Dockerfile for Unified Go Forward Framework

# Stage 1: Build SvelteKit Dashboard
FROM node:20-alpine AS dashboard-builder

# Install pnpm
RUN npm install -g pnpm

# Set working directory
WORKDIR /app/dashboard

# Copy dashboard package files
COPY dashboard/package.json dashboard/pnpm-lock.yaml* ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy dashboard source
COPY dashboard/ .

# Build dashboard
RUN pnpm build

# Stage 2: Build Go Application
FROM golang:1.25.1-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY migrations/ ./migrations/

# Copy built dashboard from previous stage
COPY --from=dashboard-builder /app/dashboard/build ./dashboard/build

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o go-forward cmd/main.go

# Stage 3: Final Runtime Image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=go-builder /app/go-forward .

# Copy migrations
COPY --from=go-builder /app/migrations ./migrations

# Create config directory
RUN mkdir -p /app/config && chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Default command
CMD ["./go-forward"]