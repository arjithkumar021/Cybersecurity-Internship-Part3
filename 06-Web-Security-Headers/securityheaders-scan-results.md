# Web Security Headers

## Overview

Security headers are HTTP response headers that instruct browsers how to behave when handling a website's content, providing important protections against various attacks.

## Testing with SecurityHeaders.com

### Scan Your Site

1. Visit: https://securityheaders.com
2. Enter your website URL
3. Review the grade and missing headers
4. Implement recommendations

**Grade Scale**:
- **A**: Excellent security
- **B-D**: Good but missing some headers
- **F**: Poor security posture

## Essential Security Headers

### 1. Content-Security-Policy (CSP)

**Purpose**: Prevents XSS, clickjacking, and other code injection attacks

**Basic Example**:
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;
```

**Strict CSP**:
```
Content-Security-Policy: 
  default-src 'none';
  script-src 'nonce-{random}';
  style-src 'nonce-{random}';
  img-src 'self';
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
```

**Directives**:
- `default-src`: Default policy for all content
- `script-src`: JavaScript sources
- `style-src`: CSS sources
- `img-src`: Image sources
- `font-src`: Font sources
- `connect-src`: AJAX, WebSocket connections
- `frame-ancestors`: Who can embed in iframe
- `base-uri`: Restricts `<base>` tag URLs
- `form-action`: Form submission targets

### 2. X-Content-Type-Options

**Purpose**: Prevents MIME-type sniffing

```
X-Content-Type-Options: nosniff
```

**Why needed**: Prevents browsers from interpreting files as a different MIME type than declared

### 3. X-Frame-Options

**Purpose**: Prevents clickjacking attacks

```
X-Frame-Options: DENY              # Never allow framing
X-Frame-Options: SAMEORIGIN        # Allow framing from same origin
X-Frame-Options: ALLOW-FROM https://trusted.com  # Deprecated
```

**Modern alternative**: Use CSP `frame-ancestors`
```
Content-Security-Policy: frame-ancestors 'none';
```

### 4. Strict-Transport-Security (HSTS)

**Purpose**: Forces HTTPS connections

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Directives**:
- `max-age=31536000`: Enforce HTTPS for 1 year
- `includeSubDomains`: Apply to all subdomains
- `preload`: Include in browser preload list

**Preload submission**: https://hstspreload.org/

### 5. X-XSS-Protection

**Purpose**: Legacy XSS filter (deprecated)

```
X-XSS-Protection: 0
```

**Note**: Recommended to disable (`0`) as it can introduce vulnerabilities. Use CSP instead.

### 6. Referrer-Policy

**Purpose**: Controls how much referrer information is shared

```
Referrer-Policy: strict-origin-when-cross-origin
```

**Options**:
- `no-referrer`: Never send
- `same-origin`: Only same origin
- `strict-origin`: Only origin, HTTPS→HTTP = none
- `strict-origin-when-cross-origin`: Full URL same-origin, origin only cross-origin

### 7. Permissions-Policy (formerly Feature-Policy)

**Purpose**: Control browser features and APIs

```
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Examples**:
```
Permissions-Policy: 
  geolocation=(self "https://maps.google.com"),
  microphone=(),
  camera=(),
  payment=(self),
  usb=()
```

### 8. Cross-Origin-Resource-Policy

**Purpose**: Prevents other origins from loading your resources

```
Cross-Origin-Resource-Policy: same-origin
```

**Options**:
- `same-origin`: Same origin only
- `same-site`: Same site
- `cross-origin`: Allow all

### 9. Cross-Origin-Opener-Policy

**Purpose**: Isolates browsing context

```
Cross-Origin-Opener-Policy: same-origin
```

### 10. Cross-Origin-Embedder-Policy

**Purpose**: Controls loading of cross-origin resources

```
Cross-Origin-Embedder-Policy: require-corp
```

## Implementation Examples

### Apache (.htaccess or httpd.conf)

```apache
# Content Security Policy
Header set Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' 'unsafe-inline';"

# X-Content-Type-Options  
Header always set X-Content-Type-Options "nosniff"

# X-Frame-Options
Header always set X-Frame-Options "DENY"

# Strict-Transport-Security
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# X-XSS-Protection (disabled)
Header always set X-XSS-Protection "0"

# Referrer-Policy
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions-Policy
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Remove server information
Header always unset X-Powered-By
Header always unset Server
ServerTokens Prod
ServerSignature Off
```

### Nginx

```nginx
# Security headers
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' 'unsafe-inline';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-XSS-Protection "0" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Remove server tokens
server_tokens off;
more_clear_headers 'Server';
more_clear_headers 'X-Powered-By';
```

### PHP

```php
<?php
// Content Security Policy
header("Content-Security-Policy: default-src 'self'; script-src 'self';");

// Other headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("X-XSS-Protection: 0");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// Remove PHP version
header_remove("X-Powered-By");
?>
```

### Node.js (Express)

```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://trusted.cdn.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: {
    action: 'deny'
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));

// Remove X-Powered-By
app.disable('x-powered-by');
```

### Django

```python
# settings.py

# Security headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# CSP (using django-csp package)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "https://trusted.cdn.com")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
```

## Testing Headers

### Browser DevTools

1. Open DevTools (F12)
2. Network tab
3. Select any request
4. View Response Headers

### cURL

```bash
curl -I https://example.com

# Specific header
curl -I https://example.com | grep "Content-Security-Policy"
```

### Online Tools

- https://securityheaders.com
- https://observatory.mozilla.org
- https://csp-evaluator.withgoogle.com

## Common Misconfigurations

### ❌ Too Permissive CSP

```
# BAD
Content-Security-Policy: default-src *; script-src *;
```

### ❌ Missing HSTS

Without HSTS, users vulnerable to SSL stripping attacks

### ❌ Unsafe CSP Directives

```
# UNSAFE
Content-Security-Policy: script-src 'unsafe-eval' 'unsafe-inline';
```

### ❌ Weak Referrer Policy

```
# Leaks full URL
Referrer-Policy: unsafe-url
```

## Best Practices

1. ✅ Implement all essential headers
2. ✅ Use strict CSP without 'unsafe-inline'/'unsafe-eval'
3. ✅ Enable HSTS with preload
4. ✅ Test headers before deploying
5. ✅ Monitor CSP violations
6. ✅ Remove server version headers
7. ✅ Regular security header audits

## CSP Reporting

```
Content-Security-Policy: 
  default-src 'self';
  report-uri /csp-violation-report;
  report-to csp-endpoint;
```

**Report-To header**:
```
Report-To: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://example.com/csp-reports"}]}
```

## Resources

- https://securityheaders.com
- https://observatory.mozilla.org
- https://csp-evaluator.withgoogle.com
- OWASP Secure Headers Project
- Mozilla Web Security Guidelines
