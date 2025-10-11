package providers

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// LDAPConfig represents LDAP configuration
type LDAPConfig struct {
	Host              string        `json:"host" yaml:"host"`
	Port              int           `json:"port" yaml:"port"`
	UseSSL            bool          `json:"use_ssl" yaml:"use_ssl"`
	SkipTLSVerify     bool          `json:"skip_tls_verify" yaml:"skip_tls_verify"`
	BindDN            string        `json:"bind_dn" yaml:"bind_dn"`
	BindPassword      string        `json:"bind_password" yaml:"bind_password"`
	BaseDN            string        `json:"base_dn" yaml:"base_dn"`
	UserFilter        string        `json:"user_filter" yaml:"user_filter"`               // e.g., "(uid=%s)"
	EmailAttribute    string        `json:"email_attribute" yaml:"email_attribute"`       // e.g., "mail"
	NameAttribute     string        `json:"name_attribute" yaml:"name_attribute"`         // e.g., "cn"
	UsernameAttribute string        `json:"username_attribute" yaml:"username_attribute"` // e.g., "uid"
	ConnectionTimeout time.Duration `json:"connection_timeout" yaml:"connection_timeout"`
	RequestTimeout    time.Duration `json:"request_timeout" yaml:"request_timeout"`
}

// LDAPAuthProvider implements LDAP authentication
type LDAPAuthProvider struct {
	*auth.BaseCustomAuthProvider
	config *LDAPConfig
}

// NewLDAPAuthProvider creates a new LDAP authentication provider
func NewLDAPAuthProvider(config *LDAPConfig) *LDAPAuthProvider {
	if config == nil {
		config = &LDAPConfig{
			Host:              "localhost",
			Port:              389,
			UseSSL:            false,
			SkipTLSVerify:     false,
			UserFilter:        "(uid=%s)",
			EmailAttribute:    "mail",
			NameAttribute:     "cn",
			UsernameAttribute: "uid",
			ConnectionTimeout: 10 * time.Second,
			RequestTimeout:    30 * time.Second,
		}
	}

	required := []string{"username", "password"}
	optional := []string{"domain"}

	return &LDAPAuthProvider{
		BaseCustomAuthProvider: auth.NewBaseCustomAuthProvider("ldap", required, optional),
		config:                 config,
	}
}

// Authenticate validates LDAP credentials and returns a user
func (p *LDAPAuthProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.User, error) {
	// Extract credentials
	username, ok := credentials["username"].(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("username is required")
	}

	password, ok := credentials["password"].(string)
	if !ok || password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Optional domain handling
	domain, _ := credentials["domain"].(string)
	if domain != "" {
		username = fmt.Sprintf("%s@%s", username, domain)
	}

	// Connect to LDAP server
	conn, err := p.connectLDAP()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// Bind with service account if configured
	if p.config.BindDN != "" && p.config.BindPassword != "" {
		err = conn.Bind(p.config.BindDN, p.config.BindPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for user
	userDN, userAttrs, err := p.searchUser(conn, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Authenticate user by binding with their credentials
	err = conn.Bind(userDN, password)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// Create user object from LDAP attributes
	user := &auth.User{
		ID:            uuid.New().String(),
		EmailVerified: true, // Assume LDAP users are verified
		PhoneVerified: false,
		Metadata:      make(map[string]interface{}),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Extract user information from LDAP attributes
	if email := p.getAttributeValue(userAttrs, p.config.EmailAttribute); email != "" {
		user.Email = &email
	}

	if usernameAttr := p.getAttributeValue(userAttrs, p.config.UsernameAttribute); usernameAttr != "" {
		user.Username = &usernameAttr
	} else {
		user.Username = &username
	}

	// Add LDAP-specific metadata
	user.Metadata["auth_provider"] = "ldap"
	user.Metadata["ldap_dn"] = userDN
	if name := p.getAttributeValue(userAttrs, p.config.NameAttribute); name != "" {
		user.Metadata["full_name"] = name
	}

	// Add all LDAP attributes to metadata for reference
	ldapAttrs := make(map[string]interface{})
	for _, attr := range userAttrs {
		if len(attr.Values) > 0 {
			if len(attr.Values) == 1 {
				ldapAttrs[attr.Name] = attr.Values[0]
			} else {
				ldapAttrs[attr.Name] = attr.Values
			}
		}
	}
	user.Metadata["ldap_attributes"] = ldapAttrs

	return user, nil
}

// ValidateCredentials validates LDAP credential format
func (p *LDAPAuthProvider) ValidateCredentials(credentials map[string]interface{}) error {
	// First call base validation
	if err := p.BaseCustomAuthProvider.ValidateCredentials(credentials); err != nil {
		return err
	}

	// Additional LDAP-specific validation
	username, ok := credentials["username"].(string)
	if !ok {
		return fmt.Errorf("username must be a string")
	}

	password, ok := credentials["password"].(string)
	if !ok {
		return fmt.Errorf("password must be a string")
	}

	if len(username) > 255 {
		return fmt.Errorf("username too long (max 255 characters)")
	}

	if len(password) > 255 {
		return fmt.Errorf("password too long (max 255 characters)")
	}

	// Validate domain if provided
	if domain, exists := credentials["domain"]; exists {
		if domainStr, ok := domain.(string); ok {
			if len(domainStr) > 255 {
				return fmt.Errorf("domain too long (max 255 characters)")
			}
		} else {
			return fmt.Errorf("domain must be a string")
		}
	}

	return nil
}

// connectLDAP establishes connection to LDAP server
func (p *LDAPAuthProvider) connectLDAP() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)

	var conn *ldap.Conn
	var err error

	if p.config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: p.config.SkipTLSVerify,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return nil, err
	}

	// Set timeouts
	conn.SetTimeout(p.config.ConnectionTimeout)

	return conn, nil
}

// searchUser searches for a user in LDAP
func (p *LDAPAuthProvider) searchUser(conn *ldap.Conn, username string) (string, []*ldap.EntryAttribute, error) {
	// Build search filter
	filter := fmt.Sprintf(p.config.UserFilter, ldap.EscapeFilter(username))

	// Define attributes to retrieve
	attributes := []string{
		p.config.EmailAttribute,
		p.config.NameAttribute,
		p.config.UsernameAttribute,
		"dn",
	}

	// Perform search
	searchRequest := ldap.NewSearchRequest(
		p.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit - we only want one result
		int(p.config.RequestTimeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", nil, err
	}

	if len(result.Entries) == 0 {
		return "", nil, fmt.Errorf("user not found")
	}

	if len(result.Entries) > 1 {
		return "", nil, fmt.Errorf("multiple users found")
	}

	entry := result.Entries[0]
	return entry.DN, entry.Attributes, nil
}

// getAttributeValue extracts a single value from LDAP attributes
func (p *LDAPAuthProvider) getAttributeValue(attributes []*ldap.EntryAttribute, name string) string {
	for _, attr := range attributes {
		if attr.Name == name && len(attr.Values) > 0 {
			return attr.Values[0]
		}
	}
	return ""
}

// UpdateConfig updates the LDAP configuration
func (p *LDAPAuthProvider) UpdateConfig(config *LDAPConfig) {
	p.config = config
}

// GetConfig returns the current LDAP configuration (without sensitive data)
func (p *LDAPAuthProvider) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"host":               p.config.Host,
		"port":               p.config.Port,
		"use_ssl":            p.config.UseSSL,
		"skip_tls_verify":    p.config.SkipTLSVerify,
		"base_dn":            p.config.BaseDN,
		"user_filter":        p.config.UserFilter,
		"email_attribute":    p.config.EmailAttribute,
		"name_attribute":     p.config.NameAttribute,
		"username_attribute": p.config.UsernameAttribute,
		"connection_timeout": p.config.ConnectionTimeout.String(),
		"request_timeout":    p.config.RequestTimeout.String(),
		// Note: bind_dn and bind_password are not included for security
	}
}
