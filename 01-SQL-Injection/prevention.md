# SQL Injection Prevention

## Best Practices

### 1. Parameterized Queries (Prepared Statements)

The most effective defense against SQL injection.

**PHP (PDO)**:
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
$stmt->execute([$username, $password]);
```

**PHP (MySQLi)**:
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

**Python**:
```python
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
```

**Node.js**:
```javascript
connection.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
```

### 2. Stored Procedures

Use stored procedures with parameterized inputs:

```sql
CREATE PROCEDURE LoginUser
    @Username NVARCHAR(50),
    @Password NVARCHAR(50)
AS
BEGIN
    SELECT * FROM Users WHERE Username = @Username AND Password = @Password
END
```

### 3. Input Validation

- **Whitelist validation**: Only allow expected characters
- **Type checking**: Ensure inputs match expected data types
- **Length restrictions**: Limit input length

**Example**:
```php
if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
    die("Invalid username format");
}
```

### 4. Escaping User Input

Last resort if parameterized queries aren't possible:

**PHP**:
```php
$username = mysqli_real_escape_string($conn, $username);
```

**Note**: This is NOT recommended as primary defense!

### 5. Least Privilege Principle

- Database users should have minimal necessary permissions
- Separate read-only and write accounts
- Avoid using root/admin accounts for web applications

```sql
-- Create limited user
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'webapp'@'localhost';
```

### 6. Web Application Firewall (WAF)

- Deploy WAF to filter malicious requests
- Examples: ModSecurity, CloudFlare WAF

### 7. Error Handling

- Never display detailed error messages to users
- Log errors securely on server-side
- Use generic error messages

**Bad**:
```php
die("MySQL Error: " . mysqli_error($conn));
```

**Good**:
```php
error_log("Database error: " . mysqli_error($conn));
die("An error occurred. Please try again later.");
```

### 8. Security Testing

- Regular penetration testing
- Automated scanning tools (SQLMap, Burp Suite)
- Code reviews

## Framework-Specific Protections

### Django (Python)
```python
# Automatically uses parameterized queries
User.objects.filter(username=username, password=password)
```

### Ruby on Rails
```ruby
# Automatically uses parameterized queries
User.where("username = ? AND password = ?", username, password)
```

### ASP.NET
```csharp
string query = "SELECT * FROM Users WHERE Username = @username AND Password = @password";
SqlCommand cmd = new SqlCommand(query, connection);
cmd.Parameters.AddWithValue("@username", username);
cmd.Parameters.AddWithValue("@password", password);
```

## Additional Resources

- OWASP SQL Injection Prevention Cheat Sheet
- SANS Top 25 Software Errors
- PCI DSS Security Requirements
