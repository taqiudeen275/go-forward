# CLI Admin Management System

A comprehensive command-line interface for managing administrators in the Unified Go Forward Framework with hierarchical admin controls, emergency access, and production-ready security features.

## 🌟 Features

- **🏗️ Hierarchical Admin System**: Four-tier admin hierarchy (System, Super, Regular, Moderator)
- **⚡ Admin Promotion/Demotion**: Seamless admin level changes with validation
- **🚨 Emergency Access**: Time-limited emergency access with IP restrictions
- **🔒 Security-First Design**: Production environment detection and enhanced security
- **📊 Comprehensive Audit**: Complete audit trails for all admin operations
- **📦 Single Executable**: All functionality in one binary

## 🚀 Quick Start

### 1. Setup
```bash
# Build the binary
go build -o go-forward cmd/main.go

# Run database migrations
./go-forward migrate up

# Create your first system admin
./go-forward admin create-system-admin --email admin@company.com
```

### 2. Basic Operations
```bash
# List all administrators
./go-forward admin list

# Promote a user to admin
./go-forward admin promote user@company.com --level regular_admin --reason "New team lead"

# Create emergency access
./go-forward admin create-emergency-access --reason "System maintenance" --duration 2h
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [📚 Complete Guide](./cli-admin-management-guide.md) | Comprehensive documentation with examples |
| [⚡ Quick Reference](./cli-admin-quick-reference.md) | Command cheat sheet and common workflows |

## 🏗️ Admin Hierarchy

```
┌─────────────────┐
│  System Admin   │ ← Full system access, can manage everyone
├─────────────────┤
│   Super Admin   │ ← Business logic, can manage Super Admin and below
├─────────────────┤
│ Regular Admin   │ ← User/content management, assigned tables
├─────────────────┤
│   Moderator     │ ← Content moderation only
└─────────────────┘
```

## 🔧 Available Commands

### Core Admin Management
- `create-system-admin` - Create system administrators
- `list` - Display all administrators with status
- `promote` - Promote users to admin or upgrade admin levels
- `demote` - Demote admins or remove admin privileges

### Emergency Access
- `create-emergency-access` - Create time-limited emergency access
- `list-emergency-access` - List emergency access entries
- `revoke-emergency-access` - Revoke active emergency access

## 🔐 Security Features

### Environment Detection
- **Development**: Simplified validation and user-friendly errors
- **Production**: Enhanced security, MFA recommendations, strict validation

### Audit Logging
- Complete audit trails for all operations
- Security event tracking
- Admin action logging with context

### Access Control
- Hierarchical permission enforcement
- Row-level security policies
- IP-based emergency access restrictions

## 💡 Usage Examples

### Admin Management
```bash
# Create system admin interactively
./go-forward admin create-system-admin

# Promote existing user to regular admin with table access
./go-forward admin promote manager@company.com \
  --level regular_admin \
  --reason "Promoted to team lead" \
  --tables users,posts,comments

# Upgrade admin to higher level
./go-forward admin promote admin@company.com \
  --level super_admin \
  --reason "Department head promotion"

# Demote admin to lower level
./go-forward admin demote admin@company.com \
  --level regular_admin \
  --reason "Role change"
```

### Emergency Access
```bash
# Create emergency access for system maintenance
./go-forward admin create-emergency-access \
  --reason "Critical database maintenance" \
  --duration 2h \
  --level system_admin

# Create IP-restricted emergency access
./go-forward admin create-emergency-access \
  --reason "Security incident response" \
  --duration 30m \
  --level super_admin \
  --ip 192.168.1.100

# List active emergency access
./go-forward admin list-emergency-access --active

# Revoke emergency access
./go-forward admin revoke-emergency-access <access-id>
```

### Admin Auditing
```bash
# List all system admins
./go-forward admin list --level system_admin

# Search for specific admin
./go-forward admin list --search john

# Export admin list for audit
./go-forward admin list > admin_audit_$(date +%Y%m%d).txt
```

## ⚙️ Configuration

### Environment Variables
```bash
export GF_DATABASE_HOST="localhost"
export GF_DATABASE_PORT="5432"
export GF_DATABASE_NAME="goforward"
export GF_DATABASE_USER="postgres"
export GF_DATABASE_PASSWORD="your-password"
export GF_AUTH_JWT_SECRET="your-jwt-secret-32-chars-min"
export GF_ENVIRONMENT="production"
```

### Configuration File (config.yaml)
```yaml
database:
  host: "localhost"
  port: 5432
  name: "goforward"
  user: "postgres"
  password: "your-password"

auth:
  jwt_secret: "your-jwt-secret"
  password_min_length: 8
  bcrypt_cost: 12

admin:
  require_mfa_for_admin: true
  session_timeout: "8h"

security:
  audit_retention_days: 90
```

## 🛠️ Troubleshooting

### Common Issues

**Database Connection Error**
```bash
Error: failed to connect to database
# Solution: Check database status and connection parameters
./go-forward migrate status
```

**Permission Denied**
```bash
Error: insufficient privileges to promote this admin
# Solution: Use higher-level admin account or check hierarchy rules
./go-forward admin list --level system_admin
```

**Migration Required**
```bash
Error: relation "emergency_access" does not exist
# Solution: Run pending migrations
./go-forward migrate up
```

### Recovery Procedures

**Lost System Admin Access**
```bash
# Create new system admin (requires database access)
./go-forward admin create-system-admin --email recovery@company.com --force

# Or use existing emergency access
./go-forward admin list-emergency-access --active
```

## 📊 Status Indicators

### Admin Status
- ✅ **Active**: Normal functioning admin
- 🔒 **Locked**: Account temporarily locked  
- 🔐 **MFA Enabled**: Multi-factor authentication active

### Emergency Access Status
- 🟢 **Active**: Valid and usable
- 🚫 **Revoked**: Manually revoked
- ⏰ **Expired**: Time limit exceeded
- ✅ **Used**: Successfully used

## 🔗 Related Documentation

- [Framework Overview](../README.md)
- [Database Migrations](./migrations.md)
- [Security Guide](./security.md)
- [API Documentation](./api.md)

## 🤝 Contributing

1. Follow the existing code style and patterns
2. Add comprehensive tests for new features
3. Update documentation for any changes
4. Ensure security best practices are followed

## 📄 License

This project is part of the Unified Go Forward Framework. See the main project license for details.

---

**Need Help?** 
- 📚 [Complete Documentation](./cli-admin-management-guide.md)
- ⚡ [Quick Reference](./cli-admin-quick-reference.md)
- 🐛 [Report Issues](../issues.md)

**Version:** 1.0 | **Last Updated:** October 11, 2025