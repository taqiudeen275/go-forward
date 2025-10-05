# Gmail SMTP Troubleshooting Guide

## 🚨 Current Issue: EOF Error

The "EOF" error indicates that the SMTP connection is being closed unexpectedly. This is typically caused by authentication or security issues.

## 🔧 Step-by-Step Fix

### 1. Verify Gmail App Password

Your current password looks like an App Password: `hlrr gtdr kkxf bube`

**To create a new App Password:**

1. **Go to Google Account Settings**: https://myaccount.google.com/
2. **Security** → **2-Step Verification** (must be enabled first)
3. **App passwords** → **Select app: Mail** → **Select device: Other**
4. **Enter name**: "Go Forward Framework"
5. **Copy the 16-character password** (no spaces)

### 2. Update Configuration

Replace your current config with the new App Password:

```yaml
auth:
  smtp:
    host: "smtp.gmail.com"
    port: 587
    username: "abdulhafis384@gmail.com"
    password: "your-new-16-char-app-password"  # No spaces!
    from: "abdulhafis384@gmail.com"
    use_tls: true
```

### 3. Alternative Configuration (Port 465)

If port 587 doesn't work, try port 465 with SSL:

```yaml
auth:
  smtp:
    host: "smtp.gmail.com"
    port: 465
    username: "abdulhafis384@gmail.com"
    password: "your-app-password"
    from: "abdulhafis384@gmail.com"
    use_tls: false  # Port 465 uses SSL, not TLS
```

## 🧪 Testing Steps

### Step 1: Test SMTP Connection
```bash
./test_smtp.exe
```

### Step 2: Test OTP Sending
```bash
# Start server
./main.exe

# In another terminal, test OTP
curl -X POST http://localhost:8080/auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{
    "type": "email",
    "recipient": "abdulhafis384@gmail.com",
    "purpose": "test"
  }'
```

## 🔍 Common Issues & Solutions

### Issue 1: "Invalid credentials"
**Solution:** Generate a new App Password

### Issue 2: "Connection refused"
**Solution:** Check firewall/network settings

### Issue 3: "Authentication failed"
**Solutions:**
- Ensure 2FA is enabled on Gmail
- Use App Password, not regular password
- Check username is correct (full email)

### Issue 4: "EOF" or "Connection reset"
**Solutions:**
- Try port 465 instead of 587
- Check if your ISP blocks SMTP
- Try different network (mobile hotspot)

## 🌐 Alternative Email Providers

If Gmail continues to have issues, consider these alternatives:

### SendGrid (Recommended for Production)
```yaml
auth:
  smtp:
    host: "smtp.sendgrid.net"
    port: 587
    username: "apikey"
    password: "your-sendgrid-api-key"
    from: "noreply@yourdomain.com"
    use_tls: true
```

### Mailgun
```yaml
auth:
  smtp:
    host: "smtp.mailgun.org"
    port: 587
    username: "postmaster@your-domain.mailgun.org"
    password: "your-mailgun-password"
    from: "noreply@yourdomain.com"
    use_tls: true
```

### Outlook/Hotmail
```yaml
auth:
  smtp:
    host: "smtp-mail.outlook.com"
    port: 587
    username: "your-email@outlook.com"
    password: "your-password"
    from: "your-email@outlook.com"
    use_tls: true
```

## 🔒 Security Checklist

- ✅ 2-Factor Authentication enabled on Gmail
- ✅ Using App Password (not regular password)
- ✅ App Password is 16 characters (no spaces)
- ✅ Username is full email address
- ✅ From address matches username
- ✅ Correct port and TLS settings

## 🚀 Quick Fix Commands

### Generate New App Password and Test
```bash
# 1. Generate new App Password at: https://myaccount.google.com/apppasswords
# 2. Update config.yaml with new password
# 3. Test connection
./test_smtp.exe
```

### Try Alternative Port Configuration
```bash
# Update config.yaml to use port 465
# Change use_tls: false for port 465
./test_smtp.exe
```

## 📞 Still Having Issues?

### Debug Steps:
1. **Test with different email provider** (Outlook, Yahoo)
2. **Try from different network** (mobile hotspot)
3. **Check Gmail security settings** for blocked sign-ins
4. **Use telnet to test SMTP manually**:
   ```bash
   telnet smtp.gmail.com 587
   ```

### Temporary Workaround:
For development/testing, you can disable email OTP and use SMS only:
```yaml
auth:
  enable_email_auth: false  # Disable email OTP temporarily
  enable_phone_auth: true   # Use SMS OTP only
```

---

**Most Common Solution**: Generate a fresh App Password and ensure it's exactly 16 characters with no spaces.