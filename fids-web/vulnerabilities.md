# FIDS Web Application Vulnerabilities

## Overview
This Flight Information Display system (FIDS) contains **intentional vulnerabilities** for educational and testing purposes in a controlled environment.

## Vulnerability 1: SQL Injection (SQLi)
**Location:**
**CVE Reference:**
**CVSS Score:**
**CWE:**

**Description:**

**Vulnerable Code:**

**Exploitation:**

**Impact:**

---

## Vulnerability 2: Reflected Cross-Site Scripting (XSS)
**Location:**
**CVE Reference:**
**CVSS Score:**
**CWE:**

**Description:**

**Vulnerable Code:**

**Exploitation:**

**Impact:**

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