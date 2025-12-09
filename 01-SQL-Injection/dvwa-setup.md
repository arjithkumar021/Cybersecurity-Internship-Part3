# DVWA Setup Guide for SQL Injection Testing

## Prerequisites

- XAMPP/WAMP or Docker
- Web browser
- Text editor

## Installation Steps

### Option 1: Using Docker

```bash
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa
```

Access DVWA at `http://localhost`

### Option 2: Manual Installation

1. **Download DVWA**
   ```bash
   git clone https://github.com/digininja/DVWA.git
   ```

2. **Configure Database**
   - Copy `config/config.inc.php.dist` to `config/config.inc.php`
   - Update database credentials:
     ```php
     $_DVWA['db_server'] = '127.0.0.1';
     $_DVWA['db_database'] = 'dvwa';
     $_DVWA['db_user'] = 'root';
     $_DVWA['db_password'] = '';
     ```

3. **Setup Database**
   - Navigate to `http://localhost/dvwa/setup.php`
   - Click "Create / Reset Database"

4. **Login**
   - Username: `admin`
   - Password: `password`

## Security Levels

DVWA offers different security levels:

- **Low**: No security measures (best for learning)
- **Medium**: Some basic filtering
- **High**: Strong security measures
- **Impossible**: Properly secured (no vulnerabilities)

## SQL Injection Section

1. Login to DVWA
2. Set security level to "Low"
3. Navigate to "SQL Injection" in the left menu
4. Start testing with basic payloads

## Tips

- Start with Low security to understand basic concepts
- Gradually increase difficulty as you learn
- Use browser developer tools to inspect requests/responses
- Keep notes of successful payloads
