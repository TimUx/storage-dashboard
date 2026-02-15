# Security Policy

## Vulnerability Status

Last checked: 2026-02-15

### Current Status: ✅ No Known Vulnerabilities

All dependencies have been scanned and updated to secure versions:

| Dependency | Version | Status |
|------------|---------|--------|
| Flask | 3.0.0 | ✅ Secure |
| Flask-SQLAlchemy | 3.1.1 | ✅ Secure |
| requests | 2.31.0 | ✅ Secure |
| click | 8.1.7 | ✅ Secure |
| gunicorn | 22.0.0 | ✅ Secure (patched) |
| python-dotenv | 1.0.0 | ✅ Secure |
| tabulate | 0.9.0 | ✅ Secure |

## Recent Security Fixes

### 2026-02-15: Gunicorn HTTP Smuggling Vulnerability
- **Issue**: HTTP Request/Response Smuggling and endpoint restriction bypass
- **Affected Versions**: < 22.0.0
- **Fixed Version**: 22.0.0
- **Status**: ✅ Fixed
- **Details**: Updated gunicorn from 21.2.0 to 22.0.0

## Security Features

### Application Security
- ✅ SECRET_KEY required in production
- ✅ Debug mode disabled in production
- ✅ Configurable SSL/TLS verification
- ✅ CodeQL security scanning (0 alerts)
- ✅ Input validation on all forms
- ✅ SQL injection protection (SQLAlchemy ORM)

### Deployment Security
- ✅ Runs as non-root user (systemd)
- ✅ Environment variable configuration
- ✅ HTTPS support via reverse proxy
- ✅ Firewall configuration guidance

### API Security
- ✅ Read-only API access recommended
- ✅ Credential isolation per system
- ✅ Connection timeout protection
- ✅ SSL verification configurable

## Known Limitations

### Password Storage
⚠️ **Important**: API credentials are currently stored in plain text in the database.

**Mitigation**: 
- Use dedicated read-only accounts for storage systems
- Restrict database file permissions (chmod 600)
- Consider implementing encryption with `cryptography.fernet` for production

**Future Enhancement**: Implement credential encryption before storing in database.

## Reporting Security Issues

If you discover a security vulnerability, please report it by:

1. **Do not** open a public GitHub issue
2. Email the repository owner directly
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Best Practices

### For Administrators

1. **Use Strong Secrets**
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

2. **Enable SSL Verification in Production**
   ```bash
   echo "SSL_VERIFY=true" >> .env
   ```

3. **Use Dedicated Service Accounts**
   - Create read-only users on storage systems
   - Use minimum required permissions
   - Rotate credentials regularly

4. **Secure the Database**
   ```bash
   chmod 600 /opt/storage-dashboard/storage_dashboard.db
   chown dashboard:dashboard /opt/storage-dashboard/storage_dashboard.db
   ```

5. **Enable HTTPS**
   - Use Nginx reverse proxy with SSL/TLS
   - Obtain certificates from Let's Encrypt
   - Force HTTPS redirects

6. **Regular Updates**
   ```bash
   pip list --outdated
   pip install -r requirements.txt --upgrade
   ```

### For Developers

1. Run security scans before commits
2. Keep dependencies updated
3. Use environment variables for secrets
4. Validate all user inputs
5. Follow OWASP guidelines

## Security Checklist

Before deploying to production:

- [ ] Change default SECRET_KEY
- [ ] Set FLASK_ENV=production
- [ ] Enable SSL_VERIFY=true
- [ ] Configure HTTPS with valid certificates
- [ ] Use dedicated non-root user
- [ ] Restrict database file permissions
- [ ] Configure firewall rules
- [ ] Use read-only storage API accounts
- [ ] Enable system logging
- [ ] Set up regular backups
- [ ] Document API credentials securely
- [ ] Review and limit network access

## Compliance

This application handles storage system credentials and should be deployed with appropriate security measures based on your organization's security policies and compliance requirements (e.g., ISO 27001, SOC 2, GDPR).

## Updates

This security policy is reviewed and updated with each release. Check the repository for the latest version.
