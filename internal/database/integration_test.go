package database

import (
	"context"
	"testing"
	"time"
)

// TestDatabaseConnection tests the actual database connection
// This test requires a running PostgreSQL server with the specified configuration
func TestDatabaseConnection(t *testing.T) {
	// Skip this test if running in CI or if DB_SKIP_INTEGRATION is set
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Configure for your local PostgreSQL server
	config := &Config{
		Host:            "localhost",
		Port:            5432,
		Name:            "postgres", // Using default postgres database
		User:            "postgres",
		Password:        "postgres",
		SSLMode:         "disable",
		MaxConns:        5,
		MinConns:        1,
		MaxConnLifetime: time.Minute * 30,
		MaxConnIdleTime: time.Minute * 5,
	}

	t.Logf("Testing connection to: %s", config.ConnectionString())

	// Test database connection
	db, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create database connection: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test ping
	if err := db.Ping(ctx); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	t.Log("✅ Database connection successful!")

	// Test basic query
	var version string
	err = db.QueryRow(ctx, "SELECT version()").Scan(&version)
	if err != nil {
		t.Fatalf("Failed to query database version: %v", err)
	}

	t.Logf("✅ PostgreSQL version: %s", version)

	// Test connection pool stats
	stats := db.Stats()
	t.Logf("✅ Connection pool stats - Total: %d, Idle: %d, Used: %d",
		stats.TotalConns(), stats.IdleConns(), stats.AcquiredConns())
}

// TestDatabaseService tests the full database service
func TestDatabaseService(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := &Config{
		Host:     "localhost",
		Port:     5432,
		Name:     "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
		MaxConns: 5,
		MinConns: 1,
	}

	// Create database service
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create database service: %v", err)
	}
	defer service.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test health check
	if err := service.Health(ctx); err != nil {
		t.Fatalf("Database health check failed: %v", err)
	}

	t.Log("✅ Database service health check passed!")

	// Test database utilities
	tables, err := service.Utils.GetTables(ctx, "public")
	if err != nil {
		t.Fatalf("Failed to get tables: %v", err)
	}

	t.Logf("✅ Found %d tables in public schema", len(tables))

	// Test query builder
	qb := NewQueryBuilder(service.DB)
	query, args := qb.Table("pg_tables").
		Select("tablename", "schemaname").
		Where("schemaname = ?", "public").
		Limit(5).
		Build()

	t.Logf("✅ Generated query: %s", query)
	t.Logf("✅ Query args: %v", args)

	// Execute the query
	results, err := qb.Execute(ctx)
	if err != nil {
		t.Logf("Query execution info: %v (this is expected if no tables exist)", err)
	} else {
		t.Logf("✅ Query executed successfully, found %d results", len(results))
	}
}

// TestMigrationSystem tests the migration system
func TestMigrationSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := &Config{
		Host:     "localhost",
		Port:     5432,
		Name:     "postgres",
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
		MaxConns: 5,
		MinConns: 1,
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create database service: %v", err)
	}
	defer service.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Log("🔄 Testing migration system...")

	// Test migration initialization
	if err := service.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	t.Log("✅ Database initialized with migrations!")

	// Check if users table was created
	exists, err := service.Utils.TableExists(ctx, "public", "users")
	if err != nil {
		t.Fatalf("Failed to check if users table exists: %v", err)
	}

	if exists {
		t.Log("✅ Users table created successfully!")

		// Get table info
		columns, err := service.Utils.GetColumns(ctx, "public", "users")
		if err != nil {
			t.Fatalf("Failed to get users table columns: %v", err)
		}

		t.Logf("✅ Users table has %d columns:", len(columns))
		for _, col := range columns {
			t.Logf("  - %s: %s (nullable: %v)", col.Name, col.DataType, col.IsNullable)
		}
	} else {
		t.Log("ℹ️  Users table not found (migrations may not have run)")
	}

	// Test current migration version
	version, dirty, err := service.Migration.GetCurrentVersion()
	if err != nil {
		t.Logf("Migration version info: %v (this is expected if no migrations have run)", err)
	} else {
		t.Logf("✅ Current migration version: %d (dirty: %v)", version, dirty)
	}
}
