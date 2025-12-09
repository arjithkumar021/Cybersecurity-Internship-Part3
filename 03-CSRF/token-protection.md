# CSRF Token-Based Protection

## Overview

Anti-CSRF tokens (also called synchronizer tokens) are the most effective defense against CSRF attacks. They work by including a unique, unpredictable token with each state-changing request that must be validated by the server.

## How CSRF Tokens Work

1. **Server generates unique token** when creating session
2. **Token embedded in forms/requests** as hidden field or header
3. **User submits form** with token included
4. **Server validates token** before processing request
5. **Request rejected** if token is missing or invalid

## Implementation Examples

### PHP Implementation

**Generate Token**:
```php
<?php
session_start();

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf_token = $_SESSION['csrf_token'];
?>
```

**Embed in Form**:
```html
<form action="change-password.php" method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
    <input type="password" name="new_password">
    <button type="submit">Change Password</button>
</form>
```

**Validate Token**:
```php
<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get submitted token
    $submitted_token = $_POST['csrf_token'] ?? '';
    
    // Get session token
    $session_token = $_SESSION['csrf_token'] ?? '';
    
    // Validate token
    if (!hash_equals($session_token, $submitted_token)) {
        die("CSRF token validation failed!");
    }
    
    // Process legitimate request
    changePassword($_POST['new_password']);
}
?>
```

### Node.js/Express Implementation

**Using csurf middleware**:
```javascript
const express = require('express');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

const app = express();

// Setup middleware
app.use(cookieParser());
app.use(csrf({ cookie: true }));

// Pass token to views
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

// Form route
app.get('/form', (req, res) => {
    res.send(`
        <form action="/process" method="POST">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}">
            <input type="password" name="password">
            <button type="submit">Submit</button>
        </form>
    `);
});

// Process route (automatically validated by csrf middleware)
app.post('/process', (req, res) => {
    // CSRF token automatically validated
    res.send('Success!');
});
```

### Python/Django Implementation

**Django has built-in CSRF protection**:

```python
# views.py
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def change_password(request):
    if request.method == 'POST':
        # CSRF token automatically validated
        new_password = request.POST.get('password')
        # Process password change
        return HttpResponse('Password changed!')
    return render(request, 'change_password.html')
```

**Template**:
```html
<form method="POST">
    {% csrf_token %}
    <input type="password" name="password">
    <button type="submit">Change Password</button>
</form>
```

### Ruby on Rails Implementation

**Rails has built-in CSRF protection**:

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# Views automatically include token
<%= form_with model: @user do |f| %>
  <%= f.password_field :password %>
  <%= f.submit "Change Password" %>
<% end %>
```

### React/SPA Implementation

**Client-Side**:
```javascript
// Get CSRF token from meta tag or cookie
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

// Include in fetch requests
fetch('/api/change-password', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    credentials: 'include',
    body: JSON.stringify({ password: 'newpass123' })
});
```

**Server-Side**:
```javascript
app.post('/api/change-password', (req, res) => {
    const token = req.headers['x-csrf-token'];
    
    if (!validateToken(token, req.session.csrfToken)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    
    // Process request
    res.json({ success: true });
});
```

## Additional CSRF Protections

### 1. SameSite Cookie Attribute

```php
// PHP
setcookie('session', $value, [
    'samesite' => 'Strict', // or 'Lax'
    'httponly' => true,
    'secure' => true
]);
```

```javascript
// Express
res.cookie('session', value, {
    sameSite: 'strict', // or 'lax'
    httpOnly: true,
    secure: true
});
```

**SameSite Values**:
- **Strict**: Cookie not sent with any cross-site requests
- **Lax**: Cookie sent with top-level navigations (GET only)
- **None**: Cookie sent with all requests (requires Secure flag)

### 2. Double Submit Cookie Pattern

```php
// Set CSRF token as cookie AND require in request
setcookie('csrf_token', $token, ['samesite' => 'Strict']);

// Validate
if ($_POST['csrf_token'] !== $_COOKIE['csrf_token']) {
    die('CSRF validation failed');
}
```

### 3. Custom Request Headers

```javascript
// Require custom header (AJAX requests only)
fetch('/api/action', {
    method: 'POST',
    headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-Token': token
    }
});
```

**Server validation**:
```php
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    $_SERVER['HTTP_X_REQUESTED_WITH'] !== 'XMLHttpRequest') {
    die('Invalid request');
}
```

### 4. Origin/Referer Header Validation

```php
// Validate Origin header
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed_origin = 'https://yourdomain.com';

if ($origin !== $allowed_origin) {
    die('Invalid origin');
}

// Validate Referer (fallback)
$referer = $_SERVER['HTTP_REFERER'] ?? '';
if (strpos($referer, $allowed_origin) !== 0) {
    die('Invalid referer');
}
```

### 5. Re-authentication for Sensitive Actions

```php
// Require password confirmation for critical actions
if ($action === 'delete_account') {
    if (!verifyPassword($_POST['confirm_password'], $user_id)) {
        die('Password confirmation required');
    }
}
```

## Best Practices

1. **Always use POST/PUT/DELETE** for state-changing operations
2. **Don't use GET** for any state modifications
3. **Implement CSRF tokens** for all authenticated requests
4. **Use SameSite cookies** as defense-in-depth
5. **Validate Origin/Referer headers** as additional check
6. **Require re-authentication** for critical actions
7. **Use framework protections** when available
8. **Keep tokens secret**: Don't log or include in URLs
9. **Regenerate tokens** after login
10. **Use secure token generation**: Cryptographically secure random

## Testing CSRF Protection

### Manual Testing

1. **Capture legitimate request** (Burp Suite)
2. **Remove CSRF token** from request
3. **Submit modified request**
4. **Expected**: Request should be rejected

### Automated Testing

```python
# Python script to test CSRF
import requests

# Get login page and token
session = requests.Session()
resp = session.get('http://site.com/login')

# Login without CSRF token (should fail)
resp = session.post('http://site.com/login', data={
    'username': 'admin',
    'password': 'password'
    # Missing CSRF token
})

if resp.status_code == 403:
    print("✓ CSRF protection working")
else:
    print("✗ CSRF vulnerability found!")
```

## Common Mistakes

❌ **Validating token only if present**:
```php
// WRONG
if (isset($_POST['csrf_token']) && $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Invalid token');
}
// Attacker can bypass by not sending token!
```

✅ **Always require token**:
```php
// CORRECT
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Invalid token');
}
```

❌ **Using weak token generation**:
```php
// WRONG
$token = md5(time());
```

✅ **Use cryptographically secure random**:
```php
// CORRECT
$token = bin2hex(random_bytes(32));
```

## Resources

- OWASP CSRF Prevention Cheat Sheet
- OWASP Cross-Site Request Forgery (CSRF)
- SameSite Cookie Attribute Documentation
- CWE-352: Cross-Site Request Forgery
