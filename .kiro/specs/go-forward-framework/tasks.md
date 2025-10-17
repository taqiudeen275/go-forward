# Implementation Plan

- [x] 1. Set up project structure and core interfaces





  - Create Go module with proper directory structure (cmd, internal, pkg, migrations, etc.)
  - Define core interfaces for all services (AuthService, APIService, RealtimeService, etc.)
  - Set up configuration management with YAML support
  - Create basic logging and error handling utilities
  - _Requirements: 8.1, 8.2, 8.3_

- [x] 2. Implement database foundation and connection management





  - Set up PostgreSQL connection with pgx driver and connection pooling
  - Create database migration system with up/down migration support
  - Implement basic database utilities and query builders
  - Set up initial database schema for users, migrations, and metadata tables
  - _Requirements: 2.1, 7.1, 7.3_

- [-] 3. Build authentication service core





  - [x] 3.1 Implement user model and database operations


    - Create User struct and database table
    - Implement user CRUD operations with proper validation
    - Add password hashing with bcrypt
    - _Requirements: 1.3, 1.6_



  - [x] 3.2 Implement JWT token management
    - Create JWT token generation and validation
    - Implement access and refresh token logic
    - Add token middleware for request authentication

    - _Requirements: 1.4, 1.7_

  - [x] 3.3 Add traditional email/username/phone authentication



    - Implement login endpoint with credential validation
    - Add user registration with email/username/phone support
    - Create password reset functionality
    - _Requirements: 1.3, 1.6_

  - [x] 3.4 Write authentication service unit tests






    - Test user registration and login flows
    - Test JWT token generation and validation
    - Test password hashing and validation
    - _Requirements: 1.3, 1.4, 1.6, 1.7_

- [x] 4. Implement OTP authentication system





  - [x] 4.1 Create OTP generation and storage


    - Implement OTP generation with configurable expiration
    - Create OTP storage in database with cleanup mechanism
    - Add OTP validation logic
    - _Requirements: 1.1, 1.2_

  - [x] 4.2 Add email OTP delivery


    - Integrate SMTP client for email sending
    - Create email templates for OTP messages
    - Implement email OTP sending endpoint
    - _Requirements: 1.1_



  - [x] 4.3 Add SMS OTP delivery
    - Integrate SMS provider (Arkesel)
    - Implement SMS OTP sending endpoint
    - Add phone number validation
    - _Requirements: 1.2_

  - [ ]* 4.4 Write OTP system unit tests
    - Test OTP generation and validation
    - Test email and SMS delivery mechanisms
    - Test OTP expiration and cleanup
    - _Requirements: 1.1, 1.2_

- [x] 5. Build database meta service





  - [x] 5.1 Implement database introspection


    - Create functions to read table schemas from PostgreSQL
    - Implement column metadata extraction
    - Add index and constraint information retrieval
    - _Requirements: 3.1, 3.2_

  - [x] 5.2 Create table management operations


    - Implement create table functionality
    - Add alter table operations (add/drop columns, modify types)
    - Create drop table functionality with safety checks
    - _Requirements: 3.3, 3.4_

  - [x] 5.3 Add SQL execution interface


    - Create secure SQL execution with prepared statements
    - Implement query result formatting
    - Add syntax validation and error handling
    - _Requirements: 3.2, 3.6_

  - [-] 5.4 Write database meta service unit tests




    - Test table introspection functionality
    - Test table creation and modification operations
    - Test SQL execution and result formatting
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 6. Implement auto-generated REST API service





  - [x] 6.1 Create dynamic endpoint generation


    - Implement automatic CRUD endpoint creation from table schemas
    - Add route registration and HTTP handler generation
    - Create request validation based on column types
    - _Requirements: 4.1, 4.3_



  - [x] 6.2 Add query parameter support
    - Implement filtering with WHERE clause generation
    - Add sorting with ORDER BY support
    - Create pagination with LIMIT and OFFSET


    - _Requirements: 4.4, 4.5_

  - [x] 6.3 Integrate authentication and authorization
    - Add JWT middleware to protect endpoints
    - Implement RLS policy enforcement
    - Create permission-based access control
    - _Requirements: 4.2, 4.6_

  - [x] 6.4 Write REST API service unit tests






    - Test endpoint generation and registration
    - Test CRUD operations with various data types
    - Test query parameters and filtering
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 7. Build real-time service foundation





  - [x] 7.1 Implement WebSocket connection management


    - Create WebSocket server with Gorilla WebSocket
    - Implement connection pooling and lifecycle management
    - Add connection authentication and authorization
    - _Requirements: 2.2, 2.5_

  - [x] 7.2 Create channel system


    - Implement channel creation and management
    - Add user subscription and unsubscription to channels
    - Create message broadcasting within channels
    - _Requirements: 2.2, 2.5_

  - [x] 7.3 Add database change streaming


    - Implement PostgreSQL logical replication listener
    - Create change event filtering and formatting
    - Add RLS policy enforcement for change events
    - _Requirements: 2.2, 2.4_

  - [x] 7.4 Write real-time service unit tests


    - Test WebSocket connection handling
    - Test channel subscription and message broadcasting
    - Test database change event processing
    - _Requirements: 2.2, 2.4, 2.5_

- [x] 8. Implement file storage service







  - [x] 8.1 Create basic file operations


    - Implement file upload with multipart form support
    - Add file download with proper MIME type handling
    - Create file deletion with cleanup
    - _Requirements: 6.1, 6.3_

  - [x] 8.2 Add access control system


    - Implement permission-based file access
    - Create bucket-level and file-level permissions
    - Add user-based access validation
    - _Requirements: 6.2, 6.6_

  - [x] 8.3 Create file metadata management



    - Store file information in database
    - Add file versioning support
    - Implement file search and listing
    - _Requirements: 6.1, 6.5_

  - [x] 8.4 Write storage service unit tests






    - Test file upload and download operations
    - Test access control and permissions
    - Test file metadata management
    - _Requirements: 6.1, 6.2, 6.3, 6.5_

- [x] 9. Build API gateway and middleware





  - [x] 9.1 Create HTTP server and routing







    - Set up Gin HTTP server with proper configuration
    - Implement service registration and route management
    - Add health check endpoints
    - _Requirements: 4.1, 8.4_



  - [x] 9.2 Add cross-cutting middleware





    - Implement CORS middleware with configurable origins
    - Add rate limiting middleware per user/IP
    - Create request logging and monitoring middleware


    - _Requirements: 4.6, 8.1_

  - [x] 9.3 Integrate all services





    - Wire up authentication service endpoints
    - Register REST API service routes
    - Add real-time WebSocket endpoints
    - Connect storage service endpoints
    - _Requirements: 1.1, 1.2, 1.3, 4.1, 6.1, 2.2_

  - [x] 9.4 Write gateway integration tests






    - Test service registration and routing
    - Test middleware functionality
    - Test end-to-end request flows
    - _Requirements: 4.1, 4.2, 8.1, 8.4_

- [x] 10. Implement migration management system





  - [x] 10.1 Create migration file management


    - Implement migration file creation with templates
    - Add migration versioning and naming conventions
    - Create migration history tracking in database
    - _Requirements: 7.1, 7.2, 7.3_


  - [x] 10.2 Build migration execution engine

    - Implement migration application with transaction safety
    - Add rollback functionality with proper validation
    - Create migration status tracking and reporting
    - _Requirements: 7.3, 7.4, 7.6_



  - [x] 10.3 Add CLI interface for migrations
    - Create command-line interface for migration operations
    - Add migration generation commands
    - Implement migration status and history commands
    - _Requirements: 7.1, 7.5_

  - [ ]* 10.4 Write migration system unit tests
    - Test migration file creation and parsing
    - Test migration execution and rollback
    - Test CLI command functionality
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [x] 11. Build custom authentication support




  - [x] 11.1 Create custom auth provider interface


    - Define CustomAuthProvider interface for extensibility
    - Implement provider registration and management
    - Add custom credential validation
    - _Requirements: 1.5_


  - [x] 11.2 Add example custom auth implementations

    - Create LDAP authentication provider example
    - Implement API key authentication provider
    - Add social login provider template
    - _Requirements: 1.5_

  - [ ]* 11.3 Write custom auth system unit tests
    - Test custom provider registration and execution
    - Test example provider implementations
    - Test provider fallback and error handling
    - _Requirements: 1.5_

- [x] 12. Implement configuration and extensibility





  - [x] 12.1 Create comprehensive configuration system


    - Implement YAML configuration loading
    - Add environment variable override support
    - Create configuration validation and defaults
    - _Requirements: 8.1, 8.3_


  - [x] 12.2 Add plugin architecture foundation

    - Create plugin interface and registration system
    - Implement plugin lifecycle management
    - Add plugin configuration and dependency injection
    - _Requirements: 8.2_



  - [x] 12.3 Create deployment and documentation setup
    - Add Docker and Docker Compose configurations
    - Create comprehensive README and API documentation
    - Implement example configurations for different environments
    - _Requirements: 8.4, 8.5_

  - [ ]* 12.4 Write configuration system unit tests
    - Test configuration loading and validation
    - Test environment variable overrides
    - Test plugin registration and management
    - _Requirements: 14.1, 14.2, 14.3_

- [ ] 13. Create Next.js admin dashboard foundation





  - [ ] 13.1 Set up Next.js project structure


    - Initialize Next.js project with TypeScript
    - Set up Tailwind CSS for styling
    - Configure authentication state management
    - _Requirements: 5.1, 5.6_



  - [ ] 13.2 Implement authentication pages
    - Create login page with email/username/phone support
    - Add OTP verification pages for email and SMS
    - Implement password reset functionality


    - _Requirements: 5.1_

  - [ ] 13.3 Build database management interface
    - Create table listing and creation pages
    - Implement visual table editor with column management
    - Add SQL editor with syntax highlighting
    - _Requirements: 5.2, 5.3_

  - [ ]* 13.4 Write dashboard component unit tests
    - Test authentication form components
    - Test table management interface components
    - Test SQL editor functionality
    - _Requirements: 5.1, 5.2, 5.3_

- [ ] 14. Implement Advanced Data Types and Relationships
  - [ ] 14.1 Add support for table relationships
    - Implement foreign key constraint creation and management
    - Add one-to-many relationship support with proper referential integrity
    - Create many-to-many relationship support with junction tables
    - Add relationship validation and cascade operations
    - _Requirements: 6.5, 6.6, 6.7, 6.9_

  - [ ] 14.2 Implement rich text field support
    - Add rich text field type with HTML content support
    - Implement rich text validation and sanitization
    - Create rich text editor integration for admin dashboard
    - Add rich text field API serialization and deserialization
    - _Requirements: 6.1_

  - [ ] 14.3 Add file reference field support
    - Implement file reference field type linking to storage system
    - Add file metadata integration (size, type, upload info)
    - Create file reference validation and integrity checking
    - Add automatic file cleanup when references are removed
    - _Requirements: 6.2, 7.6, 7.7_

  - [ ] 14.4 Implement advanced data types (JSON, Arrays)
    - Add JSON field support with validation and querying
    - Implement array field support for basic and structured types
    - Add data type validation and conversion utilities
    - Create advanced data type API serialization
    - _Requirements: 6.3, 6.4_

  - [ ]* 14.5 Write advanced data types tests
    - Test relationship creation and referential integrity
    - Test rich text field validation and serialization
    - Test file reference field functionality
    - Test JSON and array field operations
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 15. Enhanced API Services with Relationship Support
  - [ ] 15.1 Add relationship querying to REST API
    - Implement relationship expansion in API responses
    - Add nested querying support for related records
    - Create relationship filtering and sorting
    - Add eager loading optimization for relationships
    - _Requirements: 4.3, 4.6, 6.8_

  - [ ] 15.2 Enhance API with advanced data type support
    - Add rich text field API serialization with format options
    - Implement file reference field URL generation and metadata
    - Add JSON field querying and filtering capabilities
    - Create array field manipulation and querying
    - _Requirements: 4.7, 4.8, 6.1, 6.2_

  - [ ] 15.3 Add relationship-aware security controls
    - Implement relationship-based access control
    - Add cascade security checking for related records
    - Create relationship-aware field-level permissions
    - Add relationship validation in security policies
    - _Requirements: 4.6, 12.2, 12.6_

  - [ ]* 15.4 Write enhanced API tests
    - Test relationship expansion and nested queries
    - Test advanced data type API operations
    - Test relationship-aware security controls
    - Test file reference and rich text API functionality
    - _Requirements: 4.3, 4.6, 4.7, 4.8_

- [ ] 16. Complete admin dashboard features
  - [ ] 16.1 Add advanced data management interface
    - Create data grid with relationship display and editing
    - Implement rich text editor for rich text fields
    - Add file upload and management for file reference fields
    - Create JSON and array field editors with validation
    - _Requirements: 5.4, 6.1, 6.2_

  - [ ] 16.2 Implement relationship management interface
    - Create relationship visualization and editing tools
    - Add foreign key constraint management interface
    - Implement many-to-many relationship editor
    - Create relationship integrity checking and validation
    - _Requirements: 3.5, 6.5, 6.6, 6.7_

  - [ ] 16.3 Add user management and system monitoring
    - Create user listing and management pages
    - Add user role and permission management
    - Implement user activity monitoring
    - Create system metrics dashboard and log viewing
    - _Requirements: 5.5, 5.6_

  - [ ]* 16.4 Write dashboard feature unit tests
    - Test advanced data management interface components
    - Test relationship management functionality
    - Test user management and monitoring features
    - Test rich text and file reference field editors
    - _Requirements: 5.4, 5.5, 5.6, 6.1, 6.2_

- [ ] 17. Implement Admin Role Management and Security
  - [ ] 15.1 Extend user model with admin capabilities
    - Add admin_level, capabilities, and assigned_tables columns to users table
    - Implement AdminLevel enum and AdminCapabilities struct
    - Create admin role assignment and validation logic
    - Add admin role checking middleware
    - _Requirements: 9.1, 9.2, 9.6_

  - [ ] 15.2 Implement hierarchical admin permissions
    - Create role-based permission checking system
    - Implement capability-based access control
    - Add admin role inheritance and validation
    - Create admin promotion and demotion functionality
    - _Requirements: 8.2, 8.3, 8.4, 8.5_

  - [ ] 15.3 Add admin session management
    - Implement enhanced admin session tracking
    - Add session-based capability caching
    - Create admin session timeout and security controls
    - Add concurrent session management
    - _Requirements: 8.6, 9.3_

  - [ ]* 15.4 Write admin role management tests
    - Test admin role assignment and validation
    - Test hierarchical permission checking
    - Test admin session management
    - Test role-based access control
    - _Requirements: 8.1, 8.2, 8.3, 8.6_

- [ ] 18. Implement Enhanced Authentication and Security
  - [ ] 16.1 Add multi-factor authentication (MFA)
    - Implement TOTP (Time-based One-Time Password) support
    - Add backup codes generation and validation
    - Create MFA setup and verification flows
    - Add MFA requirement based on admin roles
    - _Requirements: 9.1, 9.2_

  - [ ] 16.2 Implement security monitoring and account lockout
    - Add failed login attempt tracking
    - Implement account lockout after failed attempts
    - Create suspicious activity detection
    - Add security event logging and alerting
    - _Requirements: 9.7, 10.3_

  - [ ] 16.3 Add API key management
    - Implement API key generation and validation
    - Add scoped permissions for API keys
    - Create API key expiration and rotation
    - Add API key usage tracking and monitoring
    - _Requirements: 9.5_

  - [ ]* 16.4 Write enhanced authentication tests
    - Test MFA setup and validation flows
    - Test security monitoring and lockout mechanisms
    - Test API key management functionality
    - Test enhanced session security
    - _Requirements: 9.1, 9.2, 9.5, 9.7_

- [ ] 19. Implement Audit Logging and Security Monitoring
  - [ ] 17.1 Create comprehensive audit logging system
    - Implement audit_logs table and logging service
    - Add structured logging for all admin actions
    - Create security event categorization and severity levels
    - Add audit log retention and archival policies
    - _Requirements: 10.1, 10.2, 10.6_

  - [ ] 17.2 Add security event detection and alerting
    - Implement security event monitoring service
    - Create pattern-based threat detection
    - Add real-time security alerts and notifications
    - Create security dashboard for monitoring
    - _Requirements: 10.3, 10.7_

  - [ ] 17.3 Create compliance reporting system
    - Implement audit log querying and filtering
    - Add compliance report generation
    - Create audit trail export functionality
    - Add automated compliance checking
    - _Requirements: 10.4, 10.5_

  - [ ]* 17.4 Write audit and monitoring tests
    - Test audit log completeness and accuracy
    - Test security event detection algorithms
    - Test compliance report generation
    - Test audit log retention and archival
    - _Requirements: 10.1, 10.2, 10.4_

- [ ] 20. Implement Table-Level Security Configuration
  - [ ] 18.1 Create table security configuration system
    - Implement TableSecurityConfig model and storage
    - Add table-level authentication and authorization controls
    - Create field-level permission management
    - Add ownership-based access filtering
    - _Requirements: 11.1, 11.2, 11.4_

  - [ ] 18.2 Implement API security enforcement
    - Add table security middleware to REST API service
    - Implement role-based endpoint access control
    - Create custom filter injection for SQL queries
    - Add field-level read/write restrictions
    - _Requirements: 11.2, 11.5, 11.6_

  - [ ] 18.3 Add security policy validation
    - Create security configuration validation
    - Implement conflict detection for security policies
    - Add security policy templates and presets
    - Create security configuration UI components
    - _Requirements: 11.3, 11.7_

  - [ ]* 18.4 Write table security tests
    - Test table security configuration management
    - Test API security enforcement
    - Test field-level permission controls
    - Test ownership filtering and validation
    - _Requirements: 11.1, 11.2, 11.5_

- [ ] 21. Implement CLI-Based Admin Management
  - [ ] 19.1 Create CLI admin management commands
    - Implement create-system-admin CLI command
    - Add promote-admin and list-admins commands
    - Create environment detection and validation
    - Add production-mode security requirements
    - _Requirements: 12.1, 12.2, 12.5, 12.6_

  - [ ] 19.2 Add bootstrap and deployment commands
    - Implement framework initialization commands
    - Add security policy setup and validation
    - Create deployment validation and health checks
    - Add emergency access creation and management
    - _Requirements: 12.3, 12.4_

  - [ ] 19.3 Implement environment-aware security policies
    - Add development vs production security modes
    - Create environment-specific validation rules
    - Implement stricter security for production deployments
    - Add configuration backup and restore
    - _Requirements: 12.2, 12.6_

  - [ ]* 19.4 Write CLI admin management tests
    - Test CLI admin creation and management
    - Test environment detection and validation
    - Test bootstrap and deployment commands
    - Test emergency access procedures
    - _Requirements: 12.1, 12.3, 12.4_

- [ ] 22. Enhanced Database Security and SQL Execution
  - [ ] 20.1 Implement SQL execution security
    - Add SQL query validation and sanitization
    - Implement dangerous operation detection
    - Create query execution monitoring and limits
    - Add comprehensive SQL audit logging
    - _Requirements: 3.2, 3.6, 10.1_

  - [ ] 20.2 Enhance database meta service security
    - Add admin role checking to database operations
    - Implement secure SQL execution with user context
    - Create query impact assessment
    - Add database operation audit trails
    - _Requirements: 3.2, 8.2, 10.1_

  - [ ] 20.3 Implement Row Level Security (RLS) management
    - Add RLS policy creation and management
    - Implement automatic RLS policy generation from table configs
    - Create RLS policy testing and validation
    - Add user context setting for RLS evaluation
    - _Requirements: 2.3, 2.4, 11.4_

  - [ ]* 20.4 Write database security tests
    - Test SQL validation and sanitization
    - Test dangerous operation detection
    - Test RLS policy enforcement
    - Test database operation audit logging
    - _Requirements: 2.3, 3.2, 10.1_

- [ ] 23. Update Admin Dashboard with Security Features
  - [ ] 21.1 Add admin role management interface
    - Create admin user management pages
    - Implement role assignment and permission editing
    - Add admin hierarchy visualization
    - Create admin activity monitoring dashboard
    - _Requirements: 8.1, 8.2, 10.3_

  - [ ] 21.2 Implement security monitoring dashboard
    - Create security events monitoring interface
    - Add audit log viewing and filtering
    - Implement security alerts and notifications
    - Create compliance reporting interface
    - _Requirements: 10.3, 10.4, 10.5_

  - [ ] 21.3 Add table security configuration interface
    - Create table security policy editor
    - Implement field-level permission management UI
    - Add security policy templates and wizards
    - Create security configuration validation feedback
    - _Requirements: 11.1, 11.3, 11.7_

  - [ ]* 21.4 Write security dashboard tests
    - Test admin role management interface
    - Test security monitoring dashboard
    - Test table security configuration UI
    - Test security policy validation
    - _Requirements: 8.1, 10.3, 11.1_

- [ ] 24. Migration System Enhancement
  - [ ] 22.1 Replace current migrations with comprehensive security schema
    - Replace simple user table with enhanced security schema
    - Add admin roles, capabilities, and security tables
    - Implement audit logging and security event tables
    - Add MFA, API keys, and session management tables
    - _Requirements: 8.1, 9.1, 10.1_

  - [ ] 22.2 Create security-focused migration templates
    - Add migration templates for common security patterns
    - Create RLS policy migration helpers
    - Implement security index and constraint templates
    - Add data migration utilities for security upgrades
    - _Requirements: 7.1, 8.1, 10.1_

  - [ ] 22.3 Add migration security validation
    - Implement security impact assessment for migrations
    - Add migration rollback safety checks
    - Create migration audit trail and logging
    - Add production migration approval workflows
    - _Requirements: 7.4, 7.6, 10.1_

  - [ ]* 22.4 Write enhanced migration tests
    - Test comprehensive security schema migrations
    - Test migration security validation
    - Test RLS policy migration helpers
    - Test migration audit and rollback functionality
    - _Requirements: 7.1, 7.4, 10.1_

- [ ] 25. Final Security Integration and Testing
  - [ ] 23.1 Complete end-to-end security integration
    - Integrate all security services through the API gateway
    - Implement comprehensive security middleware stack
    - Add security-aware error handling across all components
    - Create security configuration management system
    - _Requirements: All security requirements_

  - [ ] 23.2 Create security documentation and guides
    - Write comprehensive security configuration guide
    - Create admin user training materials
    - Document security best practices and recommendations
    - Build troubleshooting guide for security issues
    - _Requirements: 13.5, 13.6_

  - [ ]* 23.3 Write comprehensive security integration tests
    - Test complete admin authentication and authorization flows
    - Test table-level security enforcement end-to-end
    - Test audit logging and security monitoring
    - Test CLI admin management and bootstrap procedures
    - _Requirements: All security requirements_