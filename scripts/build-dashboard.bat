@echo off
REM Build script for the admin dashboard (Windows)

echo 🏗️  Building Admin Dashboard...

REM Navigate to dashboard directory
cd web\admin-dashboard

REM Install dependencies if needed
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    pnpm install
)

REM Build the dashboard
echo 🔨 Building SvelteKit app...
pnpm run build:embedded

echo ✅ Dashboard build complete!
echo 📁 Embedded assets are ready in internal\dashboard\embed\