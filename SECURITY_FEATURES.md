# Security Features

This document describes the security features implemented in the Storage Dashboard.

## Authentication

### Admin Login
- The admin area (`/admin`) is now password-protected
- All admin routes require authentication
- Session-based authentication using Flask-Login
- Secure password hashing using Werkzeug's PBKDF2 implementation

### Creating Admin Users
Use the CLI to create admin users:
```bash
python cli.py admin create-user --username admin --password yourpassword
```

Or interactively:
```bash
python cli.py admin create-user
```

List existing admin users:
```bash
python cli.py admin list-users
```

## Data Encryption

### Encrypted Fields
The following sensitive fields are automatically encrypted at rest:
- `api_username` - Storage system API usernames
- `api_password` - Storage system API passwords  
- `api_token` - Storage system API tokens

### Encryption Method
- **Algorithm**: Fernet (AES-128 in CBC mode with HMAC authentication)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt**: Fixed salt for consistency (derived from application context)
- **Base Key**: Derived from the `SECRET_KEY` environment variable

### Configuration
Set a strong SECRET_KEY in your environment or `.env` file:
```bash
SECRET_KEY=your-very-strong-random-key-here
```

**Important**: In production, use a cryptographically random secret key:
```python
import secrets
print(secrets.token_hex(32))
```

### Backward Compatibility
The encryption implementation supports migrating existing unencrypted data:
- If decryption fails, the system assumes the data is plaintext
- This allows gradual migration of existing systems
- New or updated systems are automatically encrypted

## Export/Import

### Security Considerations for Export
When exporting storage systems:
- **Exported data is NOT encrypted** - It contains plaintext credentials
- The export file should be treated as highly sensitive
- Store export files securely or encrypt them separately
- Use secure channels when transferring export files

### Export Process
```bash
# Via Web UI: Admin → Export button
# Downloads: storage_systems_export_YYYYMMDD_HHMMSS.json
```

### Import Process
```bash
# Via Web UI: Admin → Import button
# Upload a JSON file previously exported
```

During import:
- Credentials are automatically encrypted when stored
- Duplicate system names are skipped
- Import statistics are displayed after completion

## Session Security

### Session Configuration
- Sessions are managed by Flask's session system
- Session data is signed using the SECRET_KEY
- Sessions expire when the browser is closed (default)

### Logout
Users can logout via:
- Web UI: Click "Abmelden" in the navbar
- Sessions are invalidated server-side

## Best Practices

1. **Strong SECRET_KEY**: Use a cryptographically random key in production
2. **HTTPS**: Always use HTTPS in production to protect credentials in transit
3. **Regular Password Changes**: Change admin passwords periodically
4. **Export File Security**: Treat export files as highly confidential
5. **Backup Encryption**: Ensure database backups are encrypted
6. **Access Control**: Limit who can create admin users
7. **Audit Logs**: Consider implementing audit logging for admin actions

## Threat Model

### Protected Against
- ✅ Unauthorized access to admin functions
- ✅ Credentials exposed in database dumps
- ✅ Session hijacking (with HTTPS)
- ✅ Brute force password attacks (strong hashing)

### Not Protected Against
- ❌ Compromised SECRET_KEY (would allow decryption)
- ❌ Direct database access by privileged users
- ❌ Server-side code execution
- ❌ Physical access to the server

## Encryption Key Rotation

To rotate encryption keys:

1. Export all systems to JSON
2. Change the SECRET_KEY
3. Delete all systems from the database
4. Import systems from JSON (re-encrypted with new key)

**Note**: Direct key rotation without export/import is not currently supported.

## Compliance Notes

This implementation provides:
- **Encryption at rest** for sensitive credentials
- **Strong password hashing** (PBKDF2 with 100k iterations)
- **Session security** with signed cookies

For specific compliance requirements (GDPR, HIPAA, PCI-DSS, etc.), consult with your security team to ensure all requirements are met.
