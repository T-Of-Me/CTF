# Oracle Identity Manager CVE-2025-61757 CTF Challenge

## Project Structure

```
oracle-iam-ctf/
├── app.py                  # Flask application with vulnerable endpoints
├── exploit.py              # Automated exploitation script
├── test.sh                 # Verification test script
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Docker Compose configuration
├── requirements.txt        # Python dependencies
├── README.md               # Challenge overview and instructions
├── SOLUTION.md             # Detailed step-by-step solution
├── DEPLOYMENT.md           # Deployment and troubleshooting guide
├── .gitignore             # Git ignore patterns
├── templates/
│   ├── login.html         # Oracle IAM login page
│   └── dashboard.html     # Admin dashboard with flag
└── static/
    └── css/
        └── style.css      # Professional Oracle-style CSS
```

## Component Overview

### Core Application (app.py)

**Purpose**: Simulates Oracle Identity Manager 12.2.1.4.0 with CVE-2025-61757

**Key Features**:
- Flask web application
- Vulnerable SecurityFilter implementation
- REST API endpoints
- Authentication system
- Groovy compilation endpoint (RCE)

**Vulnerable Endpoints**:
- `/identity/rest/v1/users` - User management (protected)
- `/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus` - RCE endpoint (protected)

**Bypass Mechanisms**:
- Append `;.wadl` (matrix parameter)
- Append `?WSDL` (query parameter)

### Exploitation Script (exploit.py)

**Purpose**: Automated exploitation tool

**Capabilities**:
- Vulnerability detection
- Authentication bypass
- Admin user creation
- Command execution
- Interactive shell
- Flag retrieval

**Usage**:
```bash
python3 exploit.py http://target:14000 [--auto] [--shell] [--cmd "command"]
```

### Test Script (test.sh)

**Purpose**: Automated challenge verification

**Tests**:
1. Service availability
2. Authentication requirement
3. WADL bypass
4. WSDL bypass
5. User creation
6. Remote code execution
7. Flag retrieval

### Web Interface

**Login Page (templates/login.html)**:
- Oracle corporate branding
- Professional enterprise design
- Version information display

**Dashboard (templates/dashboard.html)**:
- Identity governance interface
- User statistics
- Activity monitoring
- Flag display (for admin role)

**Styling (static/css/style.css)**:
- Oracle color scheme (#C74634, #667eea)
- Gradient backgrounds
- Responsive design
- Professional enterprise aesthetics

## Technical Implementation

### Vulnerability Simulation

The challenge accurately simulates CVE-2025-61757:

1. **SecurityFilter Pattern**:
```python
PUBLIC_ENDPOINTS = [
    r'.*\.wsdl$',
    r'.*\.wadl$'
]

def security_filter():
    full_uri = request.path + query_string
    for pattern in PUBLIC_ENDPOINTS:
        if re.search(pattern, full_uri):
            return True  # Bypass
```

2. **Authentication Bypass**:
- Matrix parameters: `/users;.wadl` → matches `.*\.wadl$`
- Query parameters: `/users?WSDL` → matches `.*\.wsdl$`

3. **Remote Code Execution**:
```python
@app.route('/iam/.../groovyscriptstatus')
@require_auth  # Bypassable
def groovy_compile():
    script = request.json.get('script')
    result = subprocess.check_output(script, shell=True)
```

### Authentication System

**Default Credentials**:
- Username: `admin`
- Password: `Oracle@2025!Admin`
- Role: `SystemAdministrator`

**User Database**:
```python
users_db = {
    'admin': {
        'password': 'Oracle@2025!Admin',
        'role': 'SystemAdministrator'
    }
}
```

**Session Management**:
- Flask sessions
- Role-based access control
- Flag visibility based on role

## Deployment Architecture

```
┌─────────────────────────────────────┐
│        Docker Container             │
│  ┌───────────────────────────────┐ │
│  │   Flask App (Port 14000)      │ │
│  │                               │ │
│  │  ┌─────────────────────────┐ │ │
│  │  │  SecurityFilter         │ │ │
│  │  │  (Vulnerable)           │ │ │
│  │  └─────────────────────────┘ │ │
│  │                               │ │
│  │  ┌─────────────────────────┐ │ │
│  │  │  REST API Endpoints     │ │ │
│  │  │  - /identity/rest/v1/*  │ │ │
│  │  │  - /iam/governance/*    │ │ │
│  │  └─────────────────────────┘ │ │
│  │                               │ │
│  │  ┌─────────────────────────┐ │ │
│  │  │  Web Interface          │ │ │
│  │  │  - Login                │ │ │
│  │  │  - Dashboard            │ │ │
│  │  └─────────────────────────┘ │ │
│  └───────────────────────────────┘ │
└─────────────────────────────────────┘
         ↓ Port 14000
    Exposed to Host
```

## Learning Path

### Beginner
1. Read README.md
2. Deploy challenge
3. Follow SOLUTION.md step-by-step
4. Understand each exploitation step

### Intermediate
1. Analyze app.py code
2. Identify vulnerability manually
3. Write custom exploit scripts
4. Test different bypass techniques

### Advanced
1. Modify SecurityFilter patterns
2. Implement additional bypass methods
3. Chain with other vulnerabilities
4. Develop automated detection tools

## CTF Integration

### Scoring System

**Flags**:
- Main flag: `FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}`
- Points: 300-500 (Medium-Hard difficulty)

**Hints** (Optional):
1. "Look at the SecurityFilter regex patterns" (-50 points)
2. "Matrix parameters can be appended to paths" (-50 points)
3. "Try adding ;.wadl to the URL" (-100 points)

### Difficulty Rating

**Overall**: Medium-Hard

**Skills Required**:
- Web application security
- REST API testing
- Authentication bypass techniques
- URI manipulation
- Command injection

**Time Estimate**:
- Beginner: 2-4 hours
- Intermediate: 30-60 minutes
- Advanced: 15-30 minutes

## Security Notes

⚠️ **WARNING**: This is a deliberately vulnerable application for educational purposes only.

**Safe Usage**:
- ✅ Isolated lab environments
- ✅ CTF competitions
- ✅ Security training
- ✅ Educational demonstrations

**Unsafe Usage**:
- ❌ Production systems
- ❌ Public networks
- ❌ Corporate infrastructure
- ❌ Unauthorized testing

## Customization Guide

### Change Flag

Edit `docker-compose.yml`:
```yaml
environment:
  - FLAG=FLAG{your_custom_flag}
```

Or edit `Dockerfile`:
```dockerfile
RUN echo "FLAG{custom}" > /flag.txt
ENV FLAG="FLAG{custom}"
```

### Modify Difficulty

**Make Easier**:
- Add hints in login page
- Display version prominently
- Include CVE number in UI

**Make Harder**:
- Remove version information
- Obfuscate endpoint names
- Add rate limiting
- Implement CAPTCHA

### Add Features

**Additional Endpoints**:
```python
@app.route('/api/custom')
@require_auth
def custom_endpoint():
    # Your code here
```

**Multiple Flags**:
```python
FLAG_1 = "FLAG{auth_bypass}"
FLAG_2 = "FLAG{rce_achieved}"
FLAG_3 = "FLAG{privilege_escalation}"
```

## Documentation

- **README.md**: Challenge overview, setup, and basic solution
- **SOLUTION.md**: Detailed walkthrough with explanations
- **DEPLOYMENT.md**: Deployment guide and troubleshooting
- **PROJECT_STRUCTURE.md**: This file - project architecture

## Version History

**v1.0** (2025-11-25):
- Initial release
- CVE-2025-61757 simulation
- Complete exploitation chain
- Professional UI design
- Comprehensive documentation

## Credits

**Vulnerability**: CVE-2025-61757 (Oracle Identity Manager)  
**Discoverers**: Adam Kues & Shubham Shah (Searchlight Cyber)  
**CVSS**: 9.8 (Critical)  
**Published**: October 2025

**Challenge Author**: Security Education Team  
**Purpose**: Educational CTF challenge  
**License**: MIT (for educational use)

## References

1. [CVE-2025-61757 Details](https://nvd.nist.gov/vuln/detail/CVE-2025-61757)
2. [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
3. [Oracle Critical Patch Update](https://www.oracle.com/security-alerts/cpuoct2025.html)
4. [Searchlight Cyber Advisory](https://searchlight.com/advisories)
5. [OWASP Authentication Bypass](https://owasp.org/www-community/attacks/Bypassing_Authentication)

## Support

For questions or issues:
- Check DEPLOYMENT.md for troubleshooting
- Review SOLUTION.md for exploitation steps
- Analyze app.py for technical details
- Run test.sh for verification

---

**Disclaimer**: This challenge is for authorized security testing and educational purposes only. Unauthorized use against real systems is illegal and unethical.
