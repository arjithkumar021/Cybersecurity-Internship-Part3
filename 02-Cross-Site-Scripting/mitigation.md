# XSS Mitigation and Prevention

## Defense Strategies

### 1. Input Validation

**Whitelist Approach** (Recommended):
```php
// Only allow alphanumeric characters
if (!preg_match('/^[a-zA-Z0-9\s]+$/', $input)) {
    die("Invalid input");
}
```

**Blacklist Approach** (Not Recommended):
```php
// Remove dangerous characters (easily bypassed)
$input = str_replace(['<', '>', '"', "'"], '', $input);
```

### 2. Output Encoding

#### HTML Context
```php
// PHP
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// Python (Flask/Jinja2)
{{ user_input | e }}

// JavaScript
const sanitized = DOMPurify.sanitize(userInput);

// Node.js
const escaped = require('escape-html')(userInput);
```

#### JavaScript Context
```php
// PHP
echo json_encode($user_input, JSON_HEX_TAG | JSON_HEX_AMP);

// Python
import json
output = json.dumps(user_input)
```

#### URL Context
```php
// PHP
echo urlencode($user_input);

// JavaScript
encodeURIComponent(userInput)
```

#### CSS Context
```php
// Avoid user input in CSS entirely
// If necessary, strictly validate
```

### 3. Content Security Policy (CSP)

**HTTP Header**:
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';
```

**Meta Tag**:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
```

**Strict CSP**:
```
Content-Security-Policy: 
  default-src 'none';
  script-src 'nonce-{random}';
  style-src 'nonce-{random}';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
```

**Implementation Example**:
```php
<?php
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: script-src 'nonce-$nonce'");
?>
<!DOCTYPE html>
<html>
<head>
    <script nonce="<?php echo $nonce; ?>">
        // Only this script will execute
        console.log('Safe script');
    </script>
</head>
</html>
```

### 4. HTTPOnly and Secure Cookies

```php
// PHP
setcookie('session', $value, [
    'httponly' => true,  // Prevents JavaScript access
    'secure' => true,     // Only sent over HTTPS
    'samesite' => 'Strict' // CSRF protection
]);

// Express.js
res.cookie('session', value, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
});
```

### 5. Framework-Specific Protections

#### React
```javascript
// React automatically escapes by default
const element = <div>{userInput}</div>; // Safe

// Dangerous (avoid)
const element = <div dangerouslySetInnerHTML={{__html: userInput}} />;
```

#### Angular
```html
<!-- Angular automatically sanitizes -->
<div>{{ userInput }}</div>

<!-- Bypass (dangerous) -->
<div [innerHTML]="userInput"></div>
```

#### Vue.js
```html
<!-- Safe -->
<div>{{ userInput }}</div>

<!-- Dangerous -->
<div v-html="userInput"></div>
```

#### Django
```html
<!-- Auto-escaped -->
<div>{{ user_input }}</div>

<!-- Manual escaping -->
{% autoescape on %}
    {{ user_input }}
{% endautoescape %}
```

### 6. DOMPurify (Client-Side Sanitization)

```javascript
// Include DOMPurify library
<script src="https://cdn.jsdelivr.net/npm/dompurify@2.4.0/dist/purify.min.js"></script>

// Sanitize HTML
const clean = DOMPurify.sanitize(dirty);
document.getElementById('output').innerHTML = clean;

// Strict configuration
const clean = DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
    ALLOWED_ATTR: []
});
```

### 7. Template Security

**Secure Template Usage**:
```php
// PHP (Twig)
{{ user_input|e }}

// Python (Jinja2)
{{ user_input|e }}

// Node.js (Handlebars)
{{user_input}} // Auto-escaped

// Raw output (dangerous)
{{{ user_input }}}
```

### 8. X-XSS-Protection Header

```
X-XSS-Protection: 1; mode=block
```

Note: Modern browsers have deprecated this in favor of CSP.

### 9. Avoiding Dangerous Sinks

**Dangerous JavaScript Functions**:
```javascript
// AVOID THESE WITH USER INPUT
eval(userInput)
setTimeout(userInput)
setInterval(userInput)
Function(userInput)
element.innerHTML = userInput
document.write(userInput)
```

**Safe Alternatives**:
```javascript
// Use textContent instead of innerHTML
element.textContent = userInput;

// Create elements programmatically
const el = document.createElement('div');
el.textContent = userInput;
```

### 10. Regular Security Testing

- **Automated Scanners**: OWASP ZAP, Burp Suite
- **Manual Testing**: Security researcher review
- **Code Reviews**: Peer review for XSS vulnerabilities
- **Penetration Testing**: Regular third-party assessments

## Complete Example: Secure Implementation

```php
<?php
// Secure comment system

// 1. Input validation
function validateComment($comment) {
    // Max length
    if (strlen($comment) > 500) {
        return false;
    }
    // Additional validation as needed
    return true;
}

// 2. Store in database (use prepared statements)
function storeComment($pdo, $comment, $userId) {
    if (!validateComment($comment)) {
        throw new Exception("Invalid comment");
    }
    
    $stmt = $pdo->prepare("INSERT INTO comments (user_id, text) VALUES (?, ?)");
    $stmt->execute([$userId, $comment]);
}

// 3. Display with proper encoding
function displayComments($pdo) {
    $stmt = $pdo->query("SELECT text FROM comments");
    
    while ($row = $stmt->fetch()) {
        // HTML encode output
        echo "<div class='comment'>";
        echo htmlspecialchars($row['text'], ENT_QUOTES, 'UTF-8');
        echo "</div>";
    }
}

// 4. Set CSP header
header("Content-Security-Policy: default-src 'self'; script-src 'self'");

// 5. Set secure cookie flags
session_set_cookie_params([
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
]);
?>
```

## Defense in Depth

Implement multiple layers:
1. ✅ Input validation
2. ✅ Output encoding
3. ✅ Content Security Policy
4. ✅ HTTPOnly cookies
5. ✅ Regular security testing
6. ✅ Security headers
7. ✅ Framework protections

## Resources

- OWASP XSS Prevention Cheat Sheet
- Content Security Policy Reference
- DOMPurify Documentation
- Google's CSP Evaluator
