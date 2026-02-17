# Admin Features Quick Start Guide

This guide covers the new administrative features added to the Storage Dashboard.

## Initial Setup

### 1. Create First Admin User

After installing the application, create your first admin user:

```bash
cd /path/to/storage-dashboard
python cli.py admin create-user --username admin --password YourSecurePassword123
```

Or use interactive mode:
```bash
python cli.py admin create-user
```

### 2. Login to Admin Area

1. Start the application: `python run.py`
2. Navigate to: `http://localhost:5000/admin/login`
3. Enter your credentials
4. You'll be redirected to the admin dashboard

## Admin Features Overview

### 📊 Storage Systems Management
- View all storage systems
- Add, edit, delete systems
- Enable/disable systems
- Re-discover system information

### ⚙️ Settings (New!)
Customize the appearance of your dashboard:

**Company Information:**
- Set custom company name
- Upload company logo (PNG, JPG, SVG, GIF)

**Color Scheme:**
- Primary color (default: #A70240 - red)
- Secondary color (default: #BED600 - yellow-green)
- Accent color (default: #0098DB - blue)
- Live color preview

**To access:** Admin → Settings button

### 📥 Import Systems (New!)
Import storage systems from a JSON file:

1. Click "Importieren" button
2. Select a JSON file (previously exported)
3. Click "Importieren"
4. Systems are imported and credentials are encrypted automatically
5. Duplicate systems (by name) are skipped

**To access:** Admin → Import button

### 📤 Export Systems (New!)
Export all storage systems to JSON:

1. Click "Exportieren" button
2. File downloads automatically: `storage_systems_export_YYYYMMDD_HHMMSS.json`

**⚠️ Warning:** Export files contain plaintext credentials! Store securely.

**To access:** Admin → Export button

### 🔒 Certificate Management
Upload and manage SSL certificates:
- CA certificates
- Root certificates
- Enable/disable certificates
- Download certificates

**To access:** Admin → Certificates button

## Customization Examples

### Example 1: Change Company Name

1. Go to Admin → Settings
2. Update "Firmenname" field
3. Click "Speichern"
4. Company name appears in navbar and page title

### Example 2: Upload Company Logo

1. Go to Admin → Settings
2. Click "Choose File" under Firmenlogo
3. Select your logo image (PNG, JPG, SVG, or GIF)
4. Click "Speichern"
5. Logo appears in navbar (replacing disk emoji)

### Example 3: Customize Colors

1. Go to Admin → Settings
2. Click on any color picker
3. Select your desired color
4. View live preview at bottom of section
5. Click "Speichern"
6. Colors apply across entire application

### Example 4: Export/Import for Backup

**Export (Backup):**
```bash
1. Login to Admin
2. Click "Exportieren"
3. Save file to secure location
```

**Import (Restore):**
```bash
1. Login to Admin
2. Click "Importieren"
3. Select previously exported JSON file
4. Click "Importieren"
5. Review import statistics
```

## Corporate Design Colors

The default colors follow your corporate identity:

| Color | Hex Code | Usage |
|-------|----------|-------|
| Primary (Red) | #A70240 | Buttons, highlights, login button |
| Secondary (Yellow-Green) | #BED600 | Success states, enabled indicators |
| Accent (Blue) | #0098DB | Table headers, links, accents |

**CMYK Values:**
- Primary: 0 / 100 / 43 / 19
- Secondary: 34 / 0 / 100 / 0  
- Accent: 85 / 21 / 0 / 0

## Security Best Practices

1. **Strong Passwords:** Use complex admin passwords (12+ characters)
2. **Logout:** Always logout when done: Click "Abmelden" in navbar
3. **Export Files:** Protect export files - they contain credentials
4. **Regular Updates:** Keep the application updated
5. **HTTPS:** Use HTTPS in production environments
6. **SECRET_KEY:** Set a strong random SECRET_KEY in production

## CLI Commands Reference

### Admin User Management
```bash
# Create admin user
python cli.py admin create-user

# List admin users
python cli.py admin list-users
```

### Storage System Management
```bash
# List all systems
python cli.py admin list

# Add new system
python cli.py admin add

# Delete system
python cli.py admin delete <system_id>

# Enable system
python cli.py admin enable <system_id>

# Disable system
python cli.py admin disable <system_id>
```

## Troubleshooting

### Can't Login
- Verify username and password
- Check that admin user exists: `python cli.py admin list-users`
- Check database file exists: `storage_dashboard.db`

### Colors Not Changing
- Clear browser cache
- Hard refresh: Ctrl+F5 (Windows/Linux) or Cmd+Shift+R (Mac)
- Check settings were saved (should see success message)

### Logo Not Displaying
- Verify file format (PNG, JPG, SVG, GIF only)
- Check file size (keep under 1MB for best performance)
- Clear browser cache

### Import Failed
- Verify JSON file format matches export format
- Check error message for specific issue
- Ensure no duplicate system names

## Next Steps

- [Security Features Documentation](SECURITY_FEATURES.md)
- [Admin Guide](ADMIN_GUIDE.md)
- [Deployment Guide](DEPLOYMENT.md)

## Support

For issues or questions:
- Check existing documentation
- Review GitHub issues
- Create new issue with detailed description
