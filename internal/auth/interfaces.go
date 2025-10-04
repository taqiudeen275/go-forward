package auth

import "context"

// UserRepositoryInterface defines the contract for user repository operations
type UserRepositoryInterface interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByPhone(ctx context.Context, phone string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByIdentifier(ctx context.Context, identifier string) (*User, error)
	Update(ctx context.Context, id string, updates *UpdateUserRequest) (*User, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *UserFilter) ([]*User, error)
	Exists(ctx context.Context, identifier string) (bool, error)
	UpdatePassword(ctx context.Context, id string, hashedPassword string) error
	CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, tokenID string) error
	CleanupExpiredPasswordResetTokens(ctx context.Context) error
}

// PasswordHasherInterface defines the contract for password hashing operations
type PasswordHasherInterface interface {
	HashPassword(password string) (string, error)
	ValidatePassword(password, hash string) error
	NeedsRehash(hash string) bool
}

// ValidatorInterface defines the contract for validation operations
type ValidatorInterface interface {
	ValidateCreateUserRequest(req *CreateUserRequest) error
	ValidateUpdateUserRequest(req *UpdateUserRequest) error
	ValidateLoginRequest(req *LoginRequest) error
	ValidatePasswordResetRequest(req *PasswordResetRequest) error
	ValidatePasswordResetConfirmRequest(req *PasswordResetConfirmRequest) error
	ValidateEmail(email string) error
	ValidatePhone(phone string) error
	ValidateUsername(username string) error
	ValidatePassword(password string) error
	ValidateUserID(id string) error
}

// AuthServiceInterface defines the contract for authentication service operations
type AuthServiceInterface interface {
	CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByPhone(ctx context.Context, phone string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByIdentifier(ctx context.Context, identifier string) (*User, error)
	UpdateUser(ctx context.Context, id string, req *UpdateUserRequest) (*User, error)
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*User, error)
	ValidatePassword(ctx context.Context, identifier, password string) (*User, error)
	UpdatePassword(ctx context.Context, id, newPassword string) error
	VerifyEmail(ctx context.Context, id string) error
	VerifyPhone(ctx context.Context, id string) error
	RequestPasswordReset(ctx context.Context, req *PasswordResetRequest) error
	ConfirmPasswordReset(ctx context.Context, req *PasswordResetConfirmRequest) error
}
