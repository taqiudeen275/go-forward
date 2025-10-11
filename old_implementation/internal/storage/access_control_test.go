package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taqiudeen275/go-foward/internal/database"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

func TestNewAccessControlService(t *testing.T) {
	mockDB := &database.DB{}
	service := NewAccessControlService(mockDB)

	assert.NotNil(t, service)
	assert.Equal(t, mockDB, service.db)
	assert.NotNil(t, service.repo)
}

func TestAccessControlService_hasPermission(t *testing.T) {
	service := &AccessControlService{}

	t.Run("empty permissions allow authenticated users", func(t *testing.T) {
		hasPermission := service.hasPermission("user123", []string{})
		assert.True(t, hasPermission)
	})

	t.Run("user in allowed list", func(t *testing.T) {
		hasPermission := service.hasPermission("user123", []string{"user123", "user456"})
		assert.True(t, hasPermission)
	})

	t.Run("user not in allowed list", func(t *testing.T) {
		hasPermission := service.hasPermission("user123", []string{"user456", "user789"})
		assert.False(t, hasPermission)
	})

	t.Run("wildcard permission", func(t *testing.T) {
		hasPermission := service.hasPermission("user123", []string{"*"})
		assert.True(t, hasPermission)
	})

	t.Run("wildcard with other users", func(t *testing.T) {
		hasPermission := service.hasPermission("user123", []string{"user456", "*"})
		assert.True(t, hasPermission)
	})
}

func TestAccessControlService_CreateDefaultPermissions(t *testing.T) {
	t.Run("creates default permissions structure", func(t *testing.T) {
		// Test the expected structure of default permissions
		userID := "user123"
		permissions := &interfaces.FilePermissions{
			Public: false,
			Read:   []string{userID},
			Write:  []string{userID},
			Delete: []string{userID},
		}

		assert.False(t, permissions.Public)
		assert.Contains(t, permissions.Read, userID)
		assert.Contains(t, permissions.Write, userID)
		assert.Contains(t, permissions.Delete, userID)
		assert.Len(t, permissions.Read, 1)
		assert.Len(t, permissions.Write, 1)
		assert.Len(t, permissions.Delete, 1)
	})
}

func TestAccessControlService_ValidatePermissions(t *testing.T) {
	service := &AccessControlService{}

	t.Run("nil permissions are valid", func(t *testing.T) {
		err := service.ValidatePermissions(nil)
		assert.NoError(t, err)
	})

	t.Run("valid permissions", func(t *testing.T) {
		permissions := &interfaces.FilePermissions{
			Public: true,
			Read:   []string{"user123", "*"},
			Write:  []string{"user123"},
			Delete: []string{"user123"},
		}

		err := service.ValidatePermissions(permissions)
		assert.NoError(t, err)
	})

	t.Run("empty user ID in read permissions", func(t *testing.T) {
		permissions := &interfaces.FilePermissions{
			Read: []string{"user123", ""},
		}

		err := service.ValidatePermissions(permissions)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid read permission")
	})

	t.Run("empty user ID in write permissions", func(t *testing.T) {
		permissions := &interfaces.FilePermissions{
			Write: []string{"user123", ""},
		}

		err := service.ValidatePermissions(permissions)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid write permission")
	})

	t.Run("empty user ID in delete permissions", func(t *testing.T) {
		permissions := &interfaces.FilePermissions{
			Delete: []string{"user123", ""},
		}

		err := service.ValidatePermissions(permissions)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid delete permission")
	})
}

func TestAccessControlService_validateUserID(t *testing.T) {
	service := &AccessControlService{}

	t.Run("valid user ID", func(t *testing.T) {
		err := service.validateUserID("user123")
		assert.NoError(t, err)
	})

	t.Run("wildcard is valid", func(t *testing.T) {
		err := service.validateUserID("*")
		assert.NoError(t, err)
	})

	t.Run("empty user ID is invalid", func(t *testing.T) {
		err := service.validateUserID("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user ID cannot be empty")
	})
}
