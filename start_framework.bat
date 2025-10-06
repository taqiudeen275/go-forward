@echo off
echo =================================
echo Go Forward Framework Startup
echo =================================
echo.

echo Checking if PostgreSQL is needed...
echo If you don't have PostgreSQL running, start it with:
echo docker run --name goforward-postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=goforward -p 5432:5432 -d postgres:15
echo.

echo Building the application...
go mod tidy
if errorlevel 1 (
    echo Failed to download dependencies
    pause
    exit /b 1
)

go build -o main.exe cmd/server/main.go
if errorlevel 1 (
    echo Failed to build server
    pause
    exit /b 1
)

go build -o migrate.exe cmd/migrate/main.go
if errorlevel 1 (
    echo Failed to build migration tool
    pause
    exit /b 1
)

echo.
echo Running database migrations...
migrate.exe -up
if errorlevel 1 (
    echo Migration failed. Make sure PostgreSQL is running and configured correctly.
    echo Check your config.yaml file.
    pause
    exit /b 1
)

echo.
echo Starting the Go Forward Framework server...
echo Server will be available at: http://localhost:8080
echo Press Ctrl+C to stop the server
echo.

main.exe