# Requirements Document

## Introduction

The Unified Go Forward Framework is a comprehensive, production-ready backend framework that combines the core Go Forward framework capabilities with advanced admin security features. This unified system provides a complete Backend-as-a-Service (BaaS) solution with multi-tiered administrative controls, robust authentication mechanisms, auto-generated APIs, real-time capabilities, and an embedded SvelteKit admin dashboard.

The framework is designed to be both a hosted BaaS solution and a customizable starter framework for developers. It implements enterprise-grade security with a hierarchical admin system (System Admin, Super Admin, Regular Admin, Moderator), comprehensive audit logging, and advanced security policies. The system follows agile development principles where each task delivers a fully working feature, and the admin dashboard is built alongside each feature rather than as a standalone component.

Key architectural decisions include:
- Single executable containing server, admin CLI, and migration tools
- All admin endpoints prefixed with `/_/` to avoid collision with framework routes
- Comprehensive documentation and Swagger API visualization after each task
- No TODO placeholders - all dependencies are implemented when needed
- Dynamic configuration reflection for new settings added by future tasks
- pnpm for frontend package management

## Requirements

### Requirement 1: Unified Multi-Method Authentication System with Admin Hierarchy

**User Story:** As a framework deployer, I want a comprehensive authentication system that supports multiple methods (OTP via email/phone, traditional credentials, custom auth models) with a hierarchical admin system, so that I can implement various authentication strategies while maintaining proper administrative controls and security boundaries.

#### Acceptance Criteria

1. WHEN a user requests OTP authentication THEN the system SHALL send a one-time password via email using customizable templates
2. WHEN a user requests OTP authentication THEN the system SHALL send a one-time password via SMS to phone number using Arkesel as the default provider with customizable templates
3. WHEN a user provides email/username/phone number and password THEN the system SHALL authenticate using traditional credentials
4. WHEN authentication is successful THEN the system SHALL issue a JWT token with appropriate role information
5. WHEN a developer creates a custom auth model THEN the system SHALL support custom authentication logic similar to PocketBase
6. WHEN the system initializes THEN it SHALL support four distinct admin levels: System Admin, Super Admin, Regular Admin, and Moderator
7. WHEN a System Admin is created THEN they SHALL have unrestricted access to all framework features including SQL execution, system configuration, and admin management
8. WHEN a Super Admin is created THEN they SHALL have business-level administrative capabilities but SHALL NOT access system-level features like raw SQL execution
9. WHEN a Regular Admin is created THEN they SHALL have limited administrative access to assigned tables and user management within their domain
10. WHEN a Moderator is created THEN they SHALL have read-only access with specific content moderation capabilities
11. IF authentication fails THEN the system SHALL return appropriate error messages and log security events
12. WHEN a JWT token is provided THEN the system SHALL validate and authorize requests based on user roles and admin hierarchy

### Requirement 2: Enhanced Database Management with Real-time and Security Features

**User Story:** As a developer, I want a PostgreSQL database with real-time capabilities, comprehensive security features, and advanced management tools, so that I can build applications with live data updates, proper access control, and enterprise-grade database management.

#### Acceptance Criteria

1. WHEN the framework initializes THEN the system SHALL connect to a PostgreSQL database with connection pooling
2. WHEN data changes occur THEN the system SHALL broadcast real-time updates to subscribed clients with proper authorization
3. WHEN RLS policies are defined THEN the system SHALL enforce row-level security based on user roles and admin hierarchy
4. WHEN database operations are performed THEN the system SHALL respect security policies and audit all operations
5. WHEN real-time subscriptions are created THEN the system SHALL manage WebSocket connections efficiently with authentication
6. WHEN tables are created THEN the system SHALL support defining foreign key relationships with cascade options
7. WHEN querying data THEN the system SHALL support optional preloading of related data to optimize performance
8. WHEN creating content fields THEN the system SHALL support rich text editor fields with HTML storage and validation
9. WHEN handling file fields THEN the system SHALL integrate with the storage system for images, videos, PDFs, and other media
10. WHEN tables are created via admin panel THEN the system SHALL automatically generate migration files for version control
11. WHEN viewing table history THEN the system SHALL show creation method (migration vs admin panel) and track all schema changes
12. IF relationship constraints would be violated THEN the system SHALL prevent the operation and provide clear error messages

### Requirement 3: Comprehensive Database Management Interface with Security Controls

**User Story:** As an administrator, I want both a SQL editor and visual interface for database management with proper security controls, so that I can create and modify database structures using my preferred method while maintaining security and audit compliance.

#### Acceptance Criteria

1. WHEN accessing the admin dashboard THEN the system SHALL provide a SQL editor interface with role-based access controls
2. WHEN using the SQL editor THEN the system SHALL execute SQL commands against the database with security validation
3. WHEN using the visual interface THEN the system SHALL allow creating tables through forms with relationship support
4. WHEN using the visual interface THEN the system SHALL allow modifying table structures with constraint validation
5. WHEN migrations are created THEN the system SHALL support both CLI and interface-based migration management with audit trails
6. WHEN SQL is executed THEN the system SHALL provide syntax highlighting, error feedback, and security warnings
7. WHEN SQL is executed THEN the system SHALL validate queries against forbidden patterns and allowed operations based on user roles
8. WHEN dangerous operations are detected THEN the system SHALL require additional confirmation and MFA verification
9. WHEN SQL execution is requested THEN the system SHALL check user roles and require appropriate permissions
10. WHEN SQL is executed THEN the system SHALL log the complete query, user context, execution time, and results
11. WHEN query validation fails THEN the system SHALL provide detailed error messages and security recommendations
12. IF unauthorized SQL access is attempted THEN the system SHALL block the request and trigger security alerts

### Requirement 4: Auto-Generated RESTful API Services with Advanced Security

**User Story:** As a developer, I want automatically generated RESTful APIs for my database tables with comprehensive security controls and field-level permissions, so that I can quickly build client applications without manually creating endpoints while maintaining proper access control.

#### Acceptance Criteria

1. WHEN a table is created THEN the system SHALL automatically generate CRUD endpoints with security middleware
2. WHEN API requests are made THEN the system SHALL validate authentication and authorization based on table configuration
3. WHEN API responses are sent THEN the system SHALL return data in JSON format with field-level filtering
4. WHEN filtering is requested THEN the system SHALL support query parameters for data filtering with security validation
5. WHEN pagination is needed THEN the system SHALL support limit and offset parameters with performance optimization
6. WHEN configuring table security THEN the system SHALL provide granular controls for authentication, authorization, and ownership requirements
7. WHEN setting API permissions THEN the system SHALL support role-based access, field-level permissions, and custom filters
8. WHEN configuring endpoints THEN the system SHALL allow enabling/disabling specific HTTP methods and setting rate limits
9. WHEN ownership is required THEN the system SHALL automatically filter data based on ownership columns and user context
10. WHEN field permissions are set THEN the system SHALL enforce read/write restrictions at the API level
11. WHEN custom filters are applied THEN the system SHALL inject SQL conditions based on user roles and context
12. IF unauthorized access is attempted THEN the system SHALL return 401/403 status codes and log security events
13. IF configuration conflicts exist THEN the system SHALL validate settings and provide clear error messages

### Requirement 5: Embedded Admin Dashboard with Role-Based Interface

**User Story:** As an administrator, I want a comprehensive admin dashboard built with SvelteKit that's embedded in the final build with role-based interfaces, so that I can manage my backend services through a modern, mobile-responsive web interface with proper security controls and appealing design.

#### Acceptance Criteria

1. WHEN accessing the dashboard THEN the system SHALL display role-appropriate dashboards and navigation with `/_/` prefix
2. WHEN managing tables THEN the system SHALL provide a visual table editor with relationship support and security configuration
3. WHEN viewing data THEN the system SHALL display table contents in a grid format with role-based field visibility
4. WHEN managing users THEN the system SHALL provide user administration tools with role assignment and hierarchy display
5. WHEN configuring settings THEN the system SHALL provide framework configuration options with security validation
6. WHEN monitoring activity THEN the system SHALL display system logs, metrics, and security events
7. WHEN using the dashboard on mobile devices THEN the system SHALL provide a fully responsive interface
8. WHEN switching themes THEN the system SHALL support light and dark mode themes with smooth transitions
9. WHEN viewing the dashboard THEN the system SHALL provide an appealing design inspired by PocketBase and Supabase dashboards
10. WHEN the framework is built THEN the system SHALL embed the dashboard in the final binary for seamless deployment
11. WHEN accessing admin management THEN the system SHALL provide interfaces for admin creation, role assignment, and permission management
12. WHEN configuring security THEN the system SHALL offer visual editors for security policies and API configurations with live preview
13. WHEN viewing audit logs THEN the system SHALL provide searchable, filterable interfaces with export capabilities and real-time updates
14. WHEN performing bulk operations THEN the system SHALL support batch actions with security confirmations
15. IF errors occur THEN the system SHALL provide user-friendly error messages and recovery suggestions

### Requirement 6: Enhanced File Storage System with Security Integration

**User Story:** As a developer, I want a file storage system with proper access controls, security scanning, and admin dashboard integration, so that I can handle file uploads and downloads securely in my applications with comprehensive management capabilities.

#### Acceptance Criteria

1. WHEN files are uploaded THEN the system SHALL store them securely with metadata and access control validation
2. WHEN file access is requested THEN the system SHALL validate permissions based on user roles and ownership
3. WHEN files are served THEN the system SHALL support proper MIME types and security headers
4. WHEN storage limits are reached THEN the system SHALL handle errors gracefully and provide clear feedback
5. WHEN files are deleted THEN the system SHALL remove them from storage and update related database records
6. WHEN file uploads occur THEN the system SHALL enforce size limits, rate limits, and content validation
7. WHEN managing files through admin dashboard THEN the system SHALL provide file browser with role-based access
8. WHEN configuring storage THEN the system SHALL support both local and cloud storage with security settings
9. WHEN files are accessed THEN the system SHALL log access attempts and maintain audit trails
10. IF unauthorized file access is attempted THEN the system SHALL deny access and log security events
11. IF malicious files are detected THEN the system SHALL quarantine them and alert administrators

### Requirement 7: Comprehensive Migration Management System

**User Story:** As a developer, I want flexible migration management through both CLI and web interface with comprehensive tracking and security controls, so that I can manage database schema changes efficiently while maintaining audit trails and security compliance.

#### Acceptance Criteria

1. WHEN migrations are created via CLI THEN the system SHALL generate migration files with proper versioning and validation
2. WHEN migrations are created via interface THEN the system SHALL generate equivalent migration files with security checks
3. WHEN migrations are applied THEN the system SHALL track migration history with detailed audit logs
4. WHEN migrations are rolled back THEN the system SHALL revert schema changes with safety validations
5. WHEN migration conflicts occur THEN the system SHALL provide clear error messages and resolution tools
6. WHEN accessing migration management THEN the system SHALL display current migration status and history through admin dashboard
7. WHEN creating migrations THEN the system SHALL provide templates and visual editors for common operations
8. WHEN applying migrations THEN the system SHALL show progress, validation results, and allow rollback if needed
9. WHEN viewing migration files THEN the system SHALL provide syntax highlighting and validation feedback
10. WHEN migration conflicts occur THEN the system SHALL provide resolution tools and merge capabilities
11. WHEN migrations are executed THEN the system SHALL log all operations and provide detailed audit trails
12. IF migration fails THEN the system SHALL maintain database integrity and provide recovery options
13. IF dangerous migrations are detected THEN the system SHALL require additional confirmation and admin privileges

### Requirement 8: Enhanced Authentication with HTTP-Only Cookies and MFA

**User Story:** As a security-conscious administrator, I want configurable HTTP-only cookie authentication support with multi-factor authentication, so that I can use secure cookie-based authentication for admin dashboard and other web applications that require enhanced security.

#### Acceptance Criteria

1. WHEN HTTP-only cookie mode is enabled THEN the system SHALL store JWT tokens in secure HTTP-only cookies
2. WHEN authentication is successful THEN the system SHALL set secure, HTTP-only cookies with proper SameSite attributes
3. WHEN requests are made with cookie authentication THEN the system SHALL validate tokens from cookies
4. WHEN logout is requested THEN the system SHALL clear authentication cookies properly
5. WHEN cookie authentication is configured THEN the system SHALL support both cookie and bearer token authentication simultaneously
6. WHEN CSRF protection is enabled THEN the system SHALL implement CSRF token validation for cookie-based requests
7. WHEN an admin logs in THEN the system SHALL support optional multi-factor authentication based on role requirements
8. WHEN MFA is enabled THEN the system SHALL support TOTP (Time-based One-Time Password) and backup codes
9. WHEN admin sessions are created THEN the system SHALL implement secure session management with configurable timeouts
10. WHEN sensitive operations are performed THEN the system SHALL require re-authentication or MFA verification
11. WHEN API keys are needed THEN the system SHALL provide API key management for service-to-service authentication
12. IF cookie authentication is disabled THEN the system SHALL fall back to bearer token authentication only
13. IF suspicious activity is detected THEN the system SHALL implement account lockout and security notifications

### Requirement 9: Comprehensive Security and Audit System

**User Story:** As a compliance officer, I want detailed audit logs, security monitoring, and comprehensive security controls, so that I can track system usage, detect security incidents, maintain compliance with security policies, and protect against various attack vectors.

#### Acceptance Criteria

1. WHEN administrative actions are performed THEN the system SHALL log user identity, action type, resource affected, and timestamp
2. WHEN sensitive operations occur THEN the system SHALL capture additional context including IP address, user agent, and session information
3. WHEN security events are detected THEN the system SHALL generate alerts and notifications to appropriate administrators
4. WHEN audit logs are accessed THEN the system SHALL provide filtering, searching, and export capabilities
5. WHEN compliance reports are needed THEN the system SHALL generate standardized audit reports
6. WHEN log retention policies are configured THEN the system SHALL automatically archive and purge old logs
7. WHEN API requests are made THEN the system SHALL enforce configurable rate limits per user, IP, and endpoint
8. WHEN rate limits are exceeded THEN the system SHALL return appropriate HTTP status codes and retry-after headers
9. WHEN suspicious traffic patterns are detected THEN the system SHALL implement progressive rate limiting and blocking
10. WHEN admin operations are performed THEN the system SHALL apply separate, more restrictive rate limits
11. WHEN WebSocket connections are established THEN the system SHALL limit concurrent connections per user and IP
12. IF audit log tampering is detected THEN the system SHALL trigger security alerts and preserve evidence
13. IF DDoS attacks are detected THEN the system SHALL activate emergency protection modes and alert administrators

### Requirement 10: Framework Configuration and Extensibility with Security

**User Story:** As a developer, I want a configurable and extensible framework with comprehensive security configuration management, so that I can customize it for different project requirements while maintaining consistent security postures across environments.

#### Acceptance Criteria

1. WHEN the framework starts THEN the system SHALL load configuration from files with environment-specific overrides
2. WHEN custom plugins are added THEN the system SHALL support plugin architecture with security validation
3. WHEN environment variables are set THEN the system SHALL override default configurations with validation
4. WHEN the framework is deployed THEN the system SHALL support different deployment environments with appropriate security policies
5. WHEN documentation is needed THEN the system SHALL provide comprehensive API documentation with Swagger integration
6. WHEN security policies are configured THEN the system SHALL support environment-specific settings and inheritance
7. WHEN configuration changes are made THEN the system SHALL validate settings and check for security implications
8. WHEN policies are updated THEN the system SHALL support gradual rollout and rollback capabilities
9. WHEN compliance requirements change THEN the system SHALL allow bulk policy updates with audit trails
10. WHEN security templates are needed THEN the system SHALL provide predefined security configurations for common use cases
11. WHEN configuration drift is detected THEN the system SHALL alert administrators and suggest corrections
12. IF configuration is invalid THEN the system SHALL provide clear validation errors and prevent deployment
13. IF insecure configurations are attempted THEN the system SHALL prevent deployment and provide security guidance

### Requirement 11: CLI-Based System Administration with Security

**User Story:** As a developer deploying the framework, I want comprehensive CLI commands for system administration with proper security controls, so that I can securely bootstrap and manage the administrative system during development and production deployment.

#### Acceptance Criteria

1. WHEN using the CLI in development mode THEN the system SHALL allow easy creation of system administrators with basic validation
2. WHEN using the CLI in production mode THEN the system SHALL require additional security measures including MFA setup and confirmation files
3. WHEN creating a system admin via CLI THEN the system SHALL validate email format, password strength, and uniqueness constraints
4. WHEN promoting a user to system admin THEN the system SHALL require existing system admin authorization and log the action
5. WHEN listing admins via CLI THEN the system SHALL display admin hierarchy, roles, and status information
6. WHEN the CLI detects production environment THEN it SHALL enforce stricter security policies and audit logging
7. WHEN managing migrations via CLI THEN the system SHALL provide comprehensive migration commands with security validation
8. WHEN managing plugins via CLI THEN the system SHALL provide plugin installation and configuration commands
9. WHEN managing configuration via CLI THEN the system SHALL provide secure configuration management commands
10. WHEN emergency access is needed THEN the system SHALL provide emergency access creation with time limits and audit trails
11. IF CLI commands are executed without proper permissions THEN the system SHALL reject the operation and provide clear error messages

### Requirement 12: Advanced Plugin and Extension Management

**User Story:** As a system administrator, I want comprehensive plugin management capabilities with security controls, so that I can install, configure, and monitor plugins without requiring system-level access while maintaining security and compliance.

#### Acceptance Criteria

1. WHEN viewing plugins THEN the system SHALL display installed plugins, their status, and configuration options through admin dashboard
2. WHEN installing plugins THEN the system SHALL validate compatibility and security requirements
3. WHEN configuring plugins THEN the system SHALL provide role-based access to plugin settings
4. WHEN plugins are updated THEN the system SHALL handle version management and migration of plugin data
5. WHEN plugin errors occur THEN the system SHALL provide debugging information and error logs
6. WHEN plugins are disabled THEN the system SHALL safely deactivate functionality without data loss
7. WHEN managing plugins via CLI THEN the system SHALL provide plugin installation and configuration commands
8. WHEN plugin security issues are detected THEN the system SHALL alert administrators and provide remediation options
9. IF plugin security issues are detected THEN the system SHALL alert administrators and provide remediation options

### Requirement 13: Cron Job and Task Management System

**User Story:** As a system administrator, I want comprehensive cron job management capabilities with security controls, so that I can schedule, monitor, and manage automated tasks through the admin interface with proper security controls and audit trails.

#### Acceptance Criteria

1. WHEN creating cron jobs THEN the system SHALL provide visual cron expression builders and validation through admin dashboard
2. WHEN scheduling jobs THEN the system SHALL support various trigger types (cron, interval, one-time, event-based)
3. WHEN jobs are executed THEN the system SHALL log execution results, duration, and any errors
4. WHEN viewing job history THEN the system SHALL provide filtering, searching, and detailed execution logs
5. WHEN jobs fail THEN the system SHALL provide alerting and retry mechanisms with exponential backoff
6. WHEN managing jobs THEN the system SHALL enforce role-based permissions for job creation and modification
7. WHEN managing jobs via CLI THEN the system SHALL provide job management commands with security validation
8. IF resource limits are exceeded THEN the system SHALL prevent job execution and alert administrators

### Requirement 14: Unified Single Executable with Dynamic Configuration

**User Story:** As a developer, I want a single executable that contains the server, admin CLI, and migration tools with dynamic configuration reflection, so that I can deploy and manage the entire framework through one binary while ensuring new configuration options are automatically available.

#### Acceptance Criteria

1. WHEN the framework is built THEN the system SHALL produce a single executable containing server, CLI, and migration functionality
2. WHEN the executable is run without arguments THEN the system SHALL start the server with embedded dashboard
3. WHEN the executable is run with CLI arguments THEN the system SHALL execute appropriate CLI commands
4. WHEN the executable is run with migration arguments THEN the system SHALL execute migration operations
5. WHEN new configuration options are added THEN the system SHALL automatically reflect them in the configuration system
6. WHEN configuration is updated THEN the system SHALL validate and apply changes without requiring restart where possible
7. WHEN the system starts THEN the system SHALL detect the execution mode (server, CLI, migration) and behave appropriately
8. WHEN deploying THEN the system SHALL require only the single executable and configuration files
9. IF configuration changes require restart THEN the system SHALL notify administrators and provide restart guidance

### Requirement 15: Customizable Communication Templates and Providers

**User Story:** As an administrator, I want customizable email and SMS templates with configurable providers, so that I can personalize communication with users while using preferred service providers like Arkesel for SMS delivery.

#### Acceptance Criteria

1. WHEN configuring SMS providers THEN the system SHALL use Arkesel as the default SMS provider
2. WHEN sending OTP via SMS THEN the system SHALL use customizable SMS templates that can be edited through the admin dashboard
3. WHEN sending OTP via email THEN the system SHALL use customizable email templates that can be edited through the admin dashboard
4. WHEN editing templates THEN the system SHALL support variables for dynamic content (user name, OTP code, expiration time, etc.)
5. WHEN configuring templates THEN the system SHALL provide template preview functionality with sample data
6. WHEN templates are modified THEN the system SHALL validate template syntax and required variables
7. WHEN multiple languages are needed THEN the system SHALL support multi-language templates
8. WHEN different purposes are used THEN the system SHALL support different templates for login, registration, verification, and password reset
9. WHEN SMS providers are configured THEN the system SHALL support multiple SMS providers with Arkesel as default
10. WHEN email providers are configured THEN the system SHALL support multiple email providers (SMTP, SendGrid, etc.)
11. IF template validation fails THEN the system SHALL provide clear error messages and prevent saving invalid templates
12. IF provider configuration is invalid THEN the system SHALL provide fallback options and clear error messages

### Requirement 16: Comprehensive Documentation and API Visualization

**User Story:** As a developer, I want comprehensive documentation and Swagger API visualization that's automatically updated with each feature, so that I can understand and integrate with the framework APIs effectively while having up-to-date documentation.

#### Acceptance Criteria

1. WHEN each task is completed THEN the system SHALL generate comprehensive documentation for the implemented feature
2. WHEN APIs are created or modified THEN the system SHALL automatically update Swagger documentation
3. WHEN accessing the admin dashboard THEN the system SHALL provide integrated API documentation viewer
4. WHEN viewing API documentation THEN the system SHALL show authentication requirements, parameters, and examples
5. WHEN configuration changes are made THEN the system SHALL update relevant documentation automatically
6. WHEN new features are added THEN the system SHALL include them in the comprehensive framework documentation
7. WHEN deploying THEN the system SHALL include all documentation in the embedded dashboard
8. WHEN developers need examples THEN the system SHALL provide working code examples for all major features
9. IF documentation becomes outdated THEN the system SHALL provide warnings and update prompts