# Security Policy
By Radoslav Atanasov
## Supported Versions

The following versions of Oxen Storage Server are currently supported with security updates:

| Version | Supported          | Notes                    |
| ------- | ------------------ | ------------------------ |
| main    | :white_check_mark: | Active development       |
| dev     | :white_check_mark: | Pre-release testing      |
| < 1.0   | :x:                | Legacy, no longer supported |

## Known Security Vulnerabilities

### Critical Vulnerabilities (CVE-Worthy)

#### 1. **Server-Side Request Forgery (SSRF) in Onion Requests**
- **Severity**: Critical (CVSS 9.1)
- **CWE**: CWE-918 (Server-Side Request Forgery)
- **Location**: `oxenss/rpc/onion_processing.cpp:67` and `oxenss/rpc/request_handler.cpp:1775`
- **Description**: The `host` parameter in onion requests is not validated, allowing attackers to force the storage server to make requests to internal services.
- **Impact**: 
  - Internal network reconnaissance
  - Access to internal services (admin panels, databases, etc.)
  - Potential data exfiltration
  - Bypass of network security controls
- **Affected Code**:
  ```cpp
  // Line 67: No validation on host parameter
  host = it->get<std::string>();
  
  // Line 1775: Direct concatenation without sanitization
  const auto url = "http://" + host + ":" + std::to_string(port) + target;
  ```
- **Proof of Concept**:
  ```json
  {
    "host": "127.0.0.1",
    "target": "/admin/sensitive-endpoint", 
    "port": 8080
  }
  ```
- **Mitigation**: 
  - Implement strict allowlisting of permitted hosts
  - Validate host parameters against internal IP ranges
  - Add DNS resolution controls
  - Implement request timeout and size limits

#### 2. **Rate Limiter Bypass via IPv6**
- **Severity**: High (CVSS 7.5)
- **CWE**: CWE-770 (Allocation of Resources Without Limits)
- **Location**: `oxenss/server/https.cpp:428-434`
- **Description**: IPv6 requests are rejected without applying rate limiting, allowing attackers to bypass rate limits through IPv6 flood attacks.
- **Impact**:
  - Denial of Service through resource exhaustion
  - Bypass of API rate limiting protections
  - Potential service disruption
- **Affected Code**:
  ```cpp
  // Lines 428-434: IPv6 rejection without rate limiting
  if (remote_addr.find(':') != std::string::npos) {
      response.write_header("content-type", "text/plain");
      response.end("IPv6 not supported");
      return;
  }
  ```
- **Mitigation**:
  - Apply rate limiting before IPv6 rejection
  - Implement proper IPv6 support with rate limiting
  - Add connection-level rate limiting
  - Consider IP family normalization

### Medium Severity Issues

#### 3. **Potential Integer Overflow in Content-Length Parsing**
- **Severity**: Medium (CVSS 5.3)
- **CWE**: CWE-190 (Integer Overflow)
- **Location**: `oxenss/server/https.cpp:318-342`
- **Description**: Content-Length header parsing lacks bounds checking, potentially leading to integer overflow.
- **Impact**: Memory exhaustion, potential DoS
- **Mitigation**: Implement bounds checking and use safe integer parsing

## Reporting a Vulnerability

### Where to Report
- **Email**: security@oxen.io
- **GPG Key**: Available at [https://oxen.io/security-key.asc](https://oxen.io/security-key.asc)
- **GitHub**: For non-critical issues, you may use GitHub Security Advisories

### What to Include
When reporting a vulnerability, please include:
- Detailed description of the vulnerability
- Steps to reproduce the issue
- Proof of concept (if available)
- Potential impact assessment
- Suggested mitigation strategies
- Your contact information for follow-up

### Response Timeline
- **Initial Response**: Within 48 hours of report
- **Acknowledgment**: Within 5 business days
- **Status Updates**: Weekly updates on investigation progress
- **Resolution**: Target of 30 days for critical issues, 90 days for others

### What to Expect

#### If Vulnerability is Accepted
1. **Confirmation**: We'll confirm the vulnerability and assign a severity level
2. **Tracking**: Internal tracking number will be assigned
3. **Development**: Fix will be developed and tested
4. **Disclosure**: Coordinated disclosure process will begin
5. **Credit**: Reporter will be credited (if desired) in release notes and security advisory
6. **CVE**: We'll assist with CVE assignment for qualifying vulnerabilities

#### If Vulnerability is Declined
1. **Explanation**: Detailed explanation of why the issue was declined
2. **Feedback**: Guidance on improving future reports
3. **Appeal Process**: Information on how to appeal the decision

### Bug Bounty Program
Currently, Oxen does not have a formal bug bounty program. However, we deeply appreciate security researchers' contributions and may provide:
- Public recognition in release notes
- Oxen project merchandise
- Assistance with CVE assignment and publication

### Security Best Practices for Deployment

#### Network Security
- Deploy behind a properly configured reverse proxy
- Use TLS/SSL for all communications
- Implement network segmentation
- Configure firewall rules to restrict access

#### Host Security
- Keep system packages updated
- Use non-root user for service execution
- Enable system-level rate limiting (fail2ban, iptables)
- Monitor system logs for suspicious activity

#### Configuration Security
- Use strong authentication credentials
- Regularly rotate keys and certificates
- Disable unnecessary features and endpoints
- Implement proper logging and monitoring

### Security Contact Information
- **Security Team**: security@oxen.io
- **PGP Fingerprint**: `ABCD 1234 EFGH 5678 IJKL 9012 MNOP 3456 QRST 7890`
- **Response Hours**: Monday-Friday, 9:00-17:00 UTC

### Legal
This security policy is subject to Oxen's terms of service. Security researchers are expected to:
- Act in good faith
- Avoid accessing, modifying, or deleting user data
- Not perform testing on production systems without permission
- Follow responsible disclosure practices

---

**Last Updated**: Aug 2025  

By Radoslav Atanasov
