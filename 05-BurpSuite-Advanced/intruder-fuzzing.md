# BurpSuite Intruder: Fuzzing Guide

## Overview

Burp Intruder is an automated attack tool for fuzzing parameters, testing authentication, brute forcing, and discovering vulnerabilities through systematic input manipulation.

## Attack Types

### 1. Sniper

- **Single payload set**
- **Iterates through each position** one at a time
- **Use case**: Testing individual parameters

**Example**:
```http
# Marked positions (§)
GET /search?q=§payload§&category=§payload§ HTTP/1.1

# Requests sent:
# 1. q=test1&category=books
# 2. q=test2&category=books
# 3. q=books&category=test1
# 4. q=books&category=test2
```

### 2. Battering Ram

- **Single payload set**
- **Same payload** in all positions simultaneously
- **Use case**: Testing when all parameters should match

**Example**:
```http
# Positions
POST /login HTTP/1.1

username=§payload§&password=§payload§

# Requests:
# 1. username=admin&password=admin
# 2. username=root&password=root
```

### 3. Pitchfork

- **Multiple payload sets**
- **Iterates in parallel** (first from set 1 with first from set 2)
- **Use case**: Testing credential pairs

**Example**:
```http
# Positions
username=§payload1§&password=§payload2§

# Payloads:
# Set 1: [admin, user, root]
# Set 2: [pass123, test123, root123]

# Requests:
# 1. username=admin&password=pass123
# 2. username=user&password=test123
# 3. username=root&password=root123
```

### 4. Cluster Bomb

- **Multiple payload sets**
- **All combinations** (cartesian product)
- **Use case**: Exhaustive testing

**Example**:
```http
# Positions
username=§payload1§&password=§payload2§

# Payloads:
# Set 1: [admin, user]
# Set 2: [pass1, pass2]

# Requests:
# 1. username=admin&password=pass1
# 2. username=admin&password=pass2
# 3. username=user&password=pass1
# 4. username=user&password=pass2
```

## Setting Up an Attack

### 1. Capture Request

- Intercept target request
- Right-click → Send to Intruder

### 2. Define Positions

**Intruder → Positions**:
- Click **"Clear §"** to remove auto-selected
- Highlight value to fuzz
- Click **"Add §"** to mark position

**Example**:
```http
POST /login HTTP/1.1

username=§test§&password=§test§&submit=Login
```

### 3. Configure Payloads

**Intruder → Payloads**:
- Select payload set (if multiple positions)
- Choose payload type
- Configure options

## Payload Types

### Simple List

```
admin
administrator
root
test
user
```

**Add manually** or **Load from file**

### Runtime File

- Read from file during attack
- Good for large wordlists

**Common wordlists**:
```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
```

### Numbers

**Settings**:
- From: `1`
- To: `1000`
- Step: `1`
- Format: Decimal

**Use case**: ID enumeration, sequential testing

### Username Generator

- Generates username combinations
- Based on names and patterns

### Custom Iterator

- Combine multiple wordlists
- Create complex payloads

**Example**: `admin'--`, `user'--`, `root'--`

### Character Substitution

- Replace characters in base word
- Good for password variations

**Base**: `password`
**Output**: `p@ssw0rd`, `passw0rd`, etc.

## Common Fuzzing Scenarios

### 1. Login Brute Force

**Setup**:
```http
POST /login HTTP/1.1

username=§admin§&password=§payload§
```

**Attack type**: Sniper  
**Payload**: Password list  
**Grep**: "Login successful", "Welcome"

### 2. SQL Injection Discovery

**Setup**:
```http
GET /product?id=§1§ HTTP/1.1
```

**Payloads**:
```
1
1'
1"
1' OR '1'='1
1' OR 1=1--
1' UNION SELECT NULL--
```

**Look for**: Error messages, different response lengths

### 3. XSS Detection

**Setup**:
```http
GET /search?q=§test§ HTTP/1.1
```

**Payloads**:
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

**Grep**: `<script>`, reflected payload

### 4. Directory Enumeration

**Setup**:
```http
GET /§admin§/ HTTP/1.1
```

**Payload**: Directory wordlist  
**Filter**: Status code != 404

### 5. Parameter Discovery

**Setup**:
```http
POST /api/user HTTP/1.1

{
  "§username§": "test"
}
```

**Payload**: Common parameter names
```
id
user_id
admin
role
email
token
```

### 6. IDOR Testing

**Setup**:
```http
GET /api/user/§1§ HTTP/1.1
```

**Payload**: Numbers 1-1000  
**Look for**: Different user data

## Filtering and Sorting Results

### Response Filters

**Intruder → Options → Grep - Match**:
```
Success
Error
Invalid
Unauthorized
Welcome
```

Check for specific strings in responses

### Status Code Filtering

**Results tab**:
- Filter by status code
- Sort by length, status
- Hide responses

**Example filters**:
- Show only: `200, 301, 302`
- Hide: `404, 403`

### Response Length Analysis

- Sort by "Length"
- Look for outliers
- Different length = different response = potential vulnerability

**Example**:
```
Request 1: Length 1234 (invalid user)
Request 2: Length 1234 (invalid user)
Request 3: Length 5678 (valid user!) ← Interesting
```

## Advanced Techniques

### Recursive Grep

**Extract values from responses**:

Intruder → Options → Grep - Extract:
- Add position
- Select text to extract
- Burp creates regex

**Use case**: Extract CSRF tokens, session IDs

### Throttling

**Control request rate**:

Intruder → Options → Resource Pool:
- Max concurrent requests: 5
- Delay between requests: 100ms

**Use case**: Avoid rate limiting, reduce detection

### Redirections

**Intruder → Options → Redirections**:
- Never
- Always
- On-site only

### Token Handling

**Auto-update tokens**:

Intruder → Options → Grep - Extract:
- Extract CSRF token from response
- Use macro to update

**Advanced**: Session Handling Rules

## Performance Optimization

### 1. Reduce Noise
- Scope filtering
- Minimize payload sets

### 2. Use Resource Pools
- Limit concurrent requests
- Prevent resource exhaustion

### 3. Selective Grep
- Only grep what's needed
- Too many grep patterns = slower

## Practice Scenarios

### Scenario 1: WordPress Username Enumeration

1. Capture login POST request
2. Set Intruder on username field
3. Load common username list
4. Grep for "Invalid password" vs "Invalid username"
5. Identify valid usernames

### Scenario 2: API Rate Limiting Test

1. Capture API request
2. Sniper attack with single payload
3. Send 1000 requests
4. Analyze response codes
5. Determine rate limit threshold

### Scenario 3: Hidden Parameter Discovery

1. Capture POST request
2. Add position for parameter name
3. Load parameter fuzzing list
4. Different response = parameter exists

## Custom Wordlists

### Create Custom List

**passwords.txt**:
```
P@ssw0rd
Password123!
Welcome2024
Admin@123
Test1234!
```

Save to:
```
C:\wordlists\custom-passwords.txt
```

Load in Intruder: Payload Options → Load

### SecLists Wordlists

```
Discovery/Web-Content/
├── common.txt
├── big.txt
├── directory-list-2.3-medium.txt

Passwords/
├── Common-Credentials/
├── Default-Credentials/
├── Leaked-Databases/

Fuzzing/
├── SQLi/
├── XSS/
├── LFI/
```

## Reporting Results

### Export Results

Results → Right-click → Save items

**Formats**:
- HTML
- XML  
- CSV

### Document Findings

For each vulnerability:
1. **Request**: Full HTTP request
2. **Response**: Relevant response
3. **Payload**: Successful payload
4. **Impact**: Explanation
5. **Remediation**: Fix recommendation

## Resources

- Burp Intruder Documentation
- SecLists GitHub Repository
- PortSwigger Web Security Academy
- OWASP Testing Guide
