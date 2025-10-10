#!/bin/bash

# Build script for the admin dashboard

set -e

echo "🏗️  Building Admin Dashboard..."

# Navigate to dashboard directory
cd web/admin-dashboard

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    pnpm install
fi

# Build the dashboard
echo "🔨 Building SvelteKit app..."
pnpm run build:embedded

echo "✅ Dashboard build complete!"
echo "📁 Embedded assets are ready in internal/dashboard/embed/"