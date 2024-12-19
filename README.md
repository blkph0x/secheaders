# secheaders
# OWASP-Compliant Security Header Checker

A Python tool to validate HTTP response headers based on OWASP's recommendations for secure web applications. This tool ensures proper configuration of essential security headers and flags misconfigurations or missing headers.

---

## Features

- **Validates OWASP-recommended security headers**:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- **Checks for deprecated headers**:
  - `X-XSS-Protection`
- **Identifies misconfigurations** and provides actionable recommendations.
- Supports multiple URL inputs via direct entry or file-based lists.
- Color-coded output for better readability.

---

## Use Cases

1. **Web Application Security**: Ensure your web server is configured with the recommended headers to protect against common vulnerabilities like XSS, clickjacking, and data leakage.
2. **DevOps & CI/CD**: Integrate the tool into your CI/CD pipeline to automatically validate security headers during deployment.
3. **Penetration Testing**: Quickly assess the security posture of web applications by analyzing their HTTP headers.
4. **Compliance**: Meet security standards and recommendations, such as those outlined by OWASP, by validating header configurations.

---

## Requirements

- **Python**: Version 3.6 or later
- **Libraries**:
  - `requests`
  - `colorama`

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/blkph0x/secheaders.git
   cd secheaders
   Run with: python secheaders.py

  
