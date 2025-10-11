# CLI Admin Management - Quick Reference

## 🚀 Quick Start

```bash
# Build and setup
go build -o go-forward cmd/main.go
./go-forward migrate up

# Create first system admin
./go-forward admin create-system-admin --email admin@company.com

# List all admins
./go-forward admin list
```

## 📋 Command Cheat Sheet

### Core Admin Commands

```bash
# System Admin Creation
./go-forward admin create-system-admin -e admin@company.com -u admin -p password

# List Admins
./go-forward admin list                           # All admins
./go-forward admin list -l system_admin          # Filter by level
./go-forward admin list -s john                  # Search by name/email
./go-forward admin list --limit 10               # Limit results

# Promote User/Admin
./go-forward admin promote user@company.com -l regular_admin -r "New role"
./go-forward admin promote user@company.com -l super_admin -t users,posts

# Demote Admin
./go-forward admin demote admin@company.com -l moderator -r "Role change"
./go-forward admin demote user@company.com -r "Remove privileges"  # Remove admin
```

### Emergency Access Commands

```bash
# Create Emergency Access
./go-forward admin create-emergency-access -r "System maintenance" -d 2h -l system_admin
./go-forward admin create-emergency-access -r "Security incident" -d 30m --ip 192.168.1.100

# List Emergency Access
./go-forward admin list-emergency-access         # All entries
./go-forward admin list-emergency-access -a      # Active only
./go-forward admin list-emergency-access --limit 5

# Revoke Emergency Access
./go-forward admin revoke-emergency-access <access-id>
```

## 🏗️ Admin Hierarchy

```
System Admin (Level 4) ← Can manage everyone
    ↓
Super Admin (Level 3)  ← Can manage Level 3 and below
    ↓
Regular Admin (Level 2) ← Can manage Level 2 and below
    ↓
Moderator (Level 1)    ← Can manage Level 1 only
```

## 🔐 Security Levels

| Level | System | Database | Users | Content | Logs |
|-------|--------|----------|-------|---------|------|
| **System Admin** | ✅ Full | ✅ Full | ✅ All | ✅ All | ✅ All |
| **Super Admin** | ❌ | ❌ | ✅ All | ✅ All | ✅ All |
| **Regular Admin** | ❌ | ❌ | ✅ Manage | ✅ Manage | ❌ |
| **Moderator** | ❌ | ❌ | ❌ | ✅ Moderate | ❌ |

## ⚡ Common Workflows

### New Employee Onboarding
```bash
# 1. Create as moderator first
./go-forward admin promote newuser@company.com -l moderator -r "New hire"

# 2. Upgrade as needed
./go-forward admin promote newuser@company.com -l regular_admin -r "Training completed"
```

### Emergency Response
```bash
# 1. Create emergency access
./go-forward admin create-emergency-access -r "Production outage" -d 1h -l system_admin

# 2. Use the token for emergency operations
# (Token provided in output)

# 3. Revoke immediately after use
./go-forward admin revoke-emergency-access <access-id>
```

### Admin Audit
```bash
# Monthly admin review
./go-forward admin list > admin_audit_$(date +%Y%m%d).txt

# Check emergency access
./go-forward admin list-emergency-access

# Review system admins
./go-forward admin list -l system_admin
```

## 🚨 Emergency Procedures

### Lost System Admin Access
```bash
# Option 1: Create new system admin (requires DB access)
./go-forward admin create-system-admin -e recovery@company.com --force

# Option 2: Use existing emergency access
./go-forward admin list-emergency-access -a
```

### Account Recovery
```bash
# Unlock locked admin
./go-forward admin promote locked-admin@company.com -l system_admin -r "Recovery"

# Reset admin level
./go-forward admin demote compromised@company.com -r "Security incident"
./go-forward admin promote compromised@company.com -l moderator -r "Restored access"
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

## 🛠️ Troubleshooting

### Common Errors
```bash
# Database connection
Error: failed to connect to database
→ Check: ./go-forward migrate status

# Permission denied
Error: insufficient privileges
→ Check: ./go-forward admin list -l system_admin

# User not found
Error: user not found
→ Check: ./go-forward admin list -s <email>

# Production safety
Error: Production environment detected
→ Add: --force flag (use carefully)
```

### Validation Rules
- **Email**: Must be valid format and unique
- **Password**: Min 8 chars, special chars required in production
- **Duration**: Max 24 hours for emergency access
- **Hierarchy**: Can only promote to your level or below
- **Self-operations**: System admins cannot demote themselves

## 🔧 Configuration

### Environment Variables
```bash
export GF_DATABASE_HOST="localhost"
export GF_DATABASE_NAME="goforward"
export GF_DATABASE_USER="postgres"
export GF_DATABASE_PASSWORD="password"
export GF_AUTH_JWT_SECRET="your-32-char-secret"
export GF_ENVIRONMENT="production"
```

### Config File (config.yaml)
```yaml
database:
  host: "localhost"
  port: 5432
  name: "goforward"
auth:
  jwt_secret: "your-secret"
  password_min_length: 8
admin:
  require_mfa_for_admin: true
```

## 📚 Help Commands

```bash
./go-forward admin --help                    # Main help
./go-forward admin create-system-admin --help  # Command help
./go-forward admin promote --help            # Promotion help
./go-forward admin list --help               # Listing help
./go-forward migrate --help                  # Migration help
```

---

**💡 Pro Tips:**
- Always provide meaningful reasons for admin changes
- Use shortest necessary duration for emergency access
- Regularly audit admin accounts and emergency access
- Enable MFA for all admins in production
- Keep multiple system admins for redundancy
- Test admin operations in development first

**🔗 Full Documentation:** [CLI Admin Management Guide](./cli-admin-management-guide.md)