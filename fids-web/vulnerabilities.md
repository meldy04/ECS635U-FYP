# FIDS Web Application Vulnerabilities

## Overview
This Flight Information Display system (FIDS) contains **intentional vulnerabilities** for educational and testing purposes in a controlled environment.

## Vulnerability 1: SQL Injection (SQLi)
**Location:** `/search` endpoint
**CVE Reference:**
**CVSS Score:**
**CWE:**

**Description:**

**Vulnerable Code:**
```python
sql = f"SELECT * FROM flights WHERE flight_number LIKE '%{search_query}%' OR airline LIKE '%{search_query}%' OR departure_city LIKE '%{search_query}%'"

```

**Exploitation:**
1. Navigate to `/search`
2. Enter payload `' OR '1'='1`
3. Observe all flights returned

**Impact:**

---

## Vulnerability 2: Reflected Cross-Site Scripting (XSS)
**Location:** `/flight/<flight_id>` endpoint
**CVE Reference:**
**CVSS Score:**
**CWE:**

**Description:**

**Vulnerable Code:**
```python
    return f"<h1>Flight not found: {flight_id}</h1><a href='/'>Back to home</a>", 404

```

**Exploitation:**
1. Navigate to `/flight/<script>alert('XSS')</script>`
2. Observe JavaScript executes in victim's browser
3. Run malicious script

**Impact:**
- Session hijacking
- Cookie theft

---

## Vulnerability 3: Weak Authentication
**Location:** `/admin` endpoint
**CVE Reference:**
**CVSS Score:**
**CWE:**

**Description:**
- Default credentials: `admin / admin123`
- Lack of password hashing
- No account lockout mechanism
- No session timeout
- Hardcoded secret key

**Vulnerable Code:**
```python
app.secret_key = 'my_top_secret_key123'
user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
```

**Exploitation:**
1. Navigate to `/admin`
2. Enter: `admin / admin123` for username / password
3. Access admin dashboard

**Impact:**
- Unauthorised admin access
- System configuration exposure
- User data access

---

## Testing Instructions
### Setup
```bash
cd fids-web
docker build -t fids-web .
docker run -p 5000:5000 fids-web
```

### Access
- Homepage: http://localhost:5000
- Search: http://localhost:5000/search
- Admin: http://localhost:5000/admin

### Test Tools
- **SQLMap:** For automated SQL injection testing
- **Burp Suite:** For manual web application testing
- **Browser DevTools:** For XSS testing