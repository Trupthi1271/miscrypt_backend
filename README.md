# MisCrypt: Integrated Cryptographic Misconfiguration & Runtime Exploitability Analyzer

## 1. Project Overview

MisCrypt is a security analysis system designed to detect cryptographic and TLS misconfigurations in modern web applications and to determine whether those weaknesses are exploitable under real-world operational conditions.

Unlike traditional security scanners that only flag insecure configurations, MisCrypt correlates:

- Static code-level cryptographic weaknesses  
- Transport-layer (TLS) misconfigurations  
- Runtime server behavior derived from logs  

This correlation enables a context-aware exploitability assessment aligned with **OWASP Top 10 – A04: Cryptographic Failures**.

---

## 2. Motivation and Problem Statement

### Existing Challenges

Many applications use HTTPS, yet still suffer from:

- Weak encryption modes such as AES-ECB  
- Deprecated hash functions like MD5 and SHA1  
- Weak or improperly sized RSA keys  
- Insecure TLS protocol and cipher configurations  

Most existing security tools:

- Report theoretical weaknesses only  
- Do not verify whether attackers are exploiting them  
- Generate high volumes of false positives  

This results in poor prioritization and alert fatigue for security teams.

### Core Insight

A cryptographic weakness is only critical if it is exploitable in real operational conditions.

MisCrypt focuses on real exploitability rather than theoretical risk.

---

## 3. High-Level Architecture

[ React Frontend ]
|
| REST APIs (JSON)
|
[ FastAPI Backend ]
|
|-- Static Cryptographic Scanner
|-- TLS & Network Scanner
|-- Runtime Log Analyzer
|-- Correlation & Risk Engine

- **Frontend**: Visualization, reporting, and user control  
- **Backend**: All security analysis and correlation logic  

---

## 4. Module 1: Static Cryptographic Analysis

### Objective

Detect insecure or incorrect cryptographic usage in application source code and Git repositories.

### Scope of Analysis

- Application source code  
- Git repositories and commit history  
- Pull requests (optional)  

### Issues Detected

- **AES in ECB mode**  
  - Pattern-based detection of ECB usage  
  - ECB mode leaks data patterns  

- **Weak hash functions**  
  - MD5  
  - SHA1  
  - Susceptible to collision attacks  

- **Weak RSA keys**  
  - Key sizes smaller than 2048 bits  

- **Hardcoded secrets**  
  - API keys  
  - Passwords  
  - Tokens  

### Implementation Details

**Technologies**
- Python  
- Semgrep and custom regex rules  
- GitPython  

**Workflow**
1. User provides a Git repository URL  
2. Backend clones the repository  
3. Code is scanned using cryptographic misuse rules  
4. Findings are stored in a structured format  

**Output**
- File name  
- Line number  
- Type of cryptographic weakness  
- Severity level  

---

## 5. Module 2: TLS and Network-Level Scanning

### Objective

Analyze how the application communicates over the network, independent of application code.

### TLS Context

TLS is typically configured at:
- Web servers (Nginx, Apache)  
- Load balancers  
- Reverse proxies  

Application source code does not directly control TLS behavior.

### Issues Detected

1. **Deprecated TLS Versions**
   - TLS 1.0 and TLS 1.1 enabled  
   - Vulnerable to known attacks  
   - Susceptible to downgrade attacks  

2. **Weak Cipher Suites**
   - RC4  
   - 3DES  
   - CBC-based ciphers  

3. **Missing HSTS**
   - Enables SSL stripping attacks  
   - First HTTP request can be hijacked  

4. **Certificate Misconfigurations**
   - Expired certificates  
   - Weak signature algorithms (e.g., SHA1)  
   - Invalid or incomplete trust chains  

### Implementation Details

**Technologies**
- Python `ssl` module  
- OpenSSL bindings  
- Custom TLS probing logic  

**Workflow**
1. Backend initiates TLS handshakes with the target server  
2. Attempts connections using:
   - Multiple TLS versions  
   - Multiple cipher suites  
3. Observes server responses  
4. Checks HTTP headers for HSTS  
5. Extracts and analyzes certificate metadata  

**Output**
- Supported TLS versions  
- Presence of weak ciphers  
- HSTS configuration status  
- Certificate issues  

---

## 6. Module 3: Runtime Exploitability Validation

### Objective

Determine whether detected cryptographic and TLS weaknesses are being actively targeted or exploited.

### Data Sources

- Nginx or Apache access logs  
- Nginx or Apache error logs  

### Runtime Indicators Analyzed

1. **Repeated TLS Handshake Failures**
   - Probing for deprecated TLS versions  
   - Cipher enumeration attempts  

2. **Protocol Downgrade Attempts**
   - Version mismatch errors  
   - Repeated retries with unsupported protocols  

3. **Abnormal Connection Patterns**
   - Rapid connection retries  
   - Non-browser TLS fingerprints  
   - Automated or scripted behavior  

### Implementation Details

**Technologies**
- Python-based log parsers  
- Regex-based pattern extraction  
- Statistical and threshold-based analysis  

**Workflow**
1. Logs are parsed line-by-line  
2. TLS-related error patterns are extracted  
3. Frequency and temporal analysis is performed  
4. Events are mapped to known attack behaviors  

**Output**
- Evidence of active exploitation attempts  
- Attack frequency and timestamps  
- Attack classification  

---

## 7. Key Contribution

MisCrypt bridges the gap between misconfiguration detection and real-world exploitability, enabling security teams to:

- Reduce false positives  
- Prioritize actionable risks  
- Align remediation efforts with actual threats  
