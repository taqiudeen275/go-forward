package database

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Host != "localhost" {
		t.Errorf("Expected host to be localhost, got %s", config.Host)
	}

	if config.Port != 5432 {
		t.Errorf("Expected port to be 5432, got %d", config.Port)
	}

	if config.MaxConns != 25 {
		t.Errorf("Expected max connections to be 25, got %d", config.MaxConns)
	}
}

func TestConnectionString(t *testing.T) {
	config := &Config{
		Host:     "localhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		Name:     "testdb",
		SSLMode:  "disable",
	}

	expected := "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=disable"
	actual := config.ConnectionString()

	if actual != expected {
		t.Errorf("Expected connection string %s, got %s", expected, actual)
	}
}

func TestNewDatabaseUtils(t *testing.T) {
	// This test would require a real database connection
	// For now, just test that the utils can be created with a nil DB
	// In a real test environment, you would set up a test database

	utils := NewDatabaseUtils(nil)
	if utils == nil {
		t.Error("Expected utils to be created, got nil")
	}
}

func TestQueryBuilder(t *testing.T) {
	// Test query builder without database connection
	qb := NewQueryBuilder(nil)

	query, args := qb.Table("users").
		Select("id", "email", "username").
		Where("email = ?", "test@example.com").
		Where("active = ?", true).
		OrderBy("created_at", "DESC").
		Limit(10).
		Offset(0).
		Build()

	expectedQuery := "SELECT id, email, username FROM users WHERE email = $1 AND active = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4"

	if query != expectedQuery {
		t.Errorf("Expected query:\n%s\nGot:\n%s", expectedQuery, query)
	}

	if len(args) != 4 {
		t.Errorf("Expected 4 arguments, got %d", len(args))
	}

	if args[0] != "test@example.com" {
		t.Errorf("Expected first arg to be 'test@example.com', got %v", args[0])
	}

	if args[1] != true {
		t.Errorf("Expected second arg to be true, got %v", args[1])
	}
}
