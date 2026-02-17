import ssl
import socket
from datetime import datetime

def run_tls_scan(domain: str, port: int = 443):
    """
    Scan TLS configuration of a domain
    """
    issues = []
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Test TLS connection
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate info
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Check TLS version
                if version in ['TLSv1', 'TLSv1.1']:
                    issues.append({
                        "issue": "Deprecated TLS Version",
                        "severity": "HIGH",
                        "details": f"Server supports {version}",
                        "description": "TLS 1.0 and 1.1 are deprecated and vulnerable",
                        "recommendation": "Disable TLS 1.0/1.1 and use TLS 1.2 or 1.3"
                    })
                
                # Check cipher suite
                if cipher:
                    cipher_name = cipher[0]
                    if any(weak in cipher_name.upper() for weak in ['RC4', '3DES', 'DES', 'MD5']):
                        issues.append({
                            "issue": "Weak Cipher Suite",
                            "severity": "HIGH",
                            "details": f"Cipher: {cipher_name}",
                            "description": "Weak or deprecated cipher suite detected",
                            "recommendation": "Use strong cipher suites (AES-GCM, ChaCha20)"
                        })
                
                # Check certificate expiry
                if cert:
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        issues.append({
                            "issue": "Expired Certificate",
                            "severity": "CRITICAL",
                            "details": f"Certificate expired {abs(days_until_expiry)} days ago",
                            "description": "SSL/TLS certificate has expired",
                            "recommendation": "Renew the certificate immediately"
                        })
                    elif days_until_expiry < 30:
                        issues.append({
                            "issue": "Certificate Expiring Soon",
                            "severity": "MEDIUM",
                            "details": f"Certificate expires in {days_until_expiry} days",
                            "description": "SSL/TLS certificate will expire soon",
                            "recommendation": "Renew the certificate"
                        })
        
        # Test for HSTS header
        try:
            import http.client
            conn = http.client.HTTPSConnection(domain, port, timeout=10)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            headers = dict(response.getheaders())
            
            if 'strict-transport-security' not in [h.lower() for h in headers.keys()]:
                issues.append({
                    "issue": "Missing HSTS Header",
                    "severity": "MEDIUM",
                    "details": "Strict-Transport-Security header not found",
                    "description": "HSTS header prevents SSL stripping attacks",
                    "recommendation": "Add Strict-Transport-Security header"
                })
            conn.close()
        except:
            pass
            
    except socket.timeout:
        issues.append({
            "issue": "Connection Timeout",
            "severity": "LOW",
            "details": f"Could not connect to {domain}:{port}",
            "description": "Connection timed out",
            "recommendation": "Verify domain and port are correct"
        })
    except Exception as e:
        issues.append({
            "issue": "Scan Error",
            "severity": "LOW",
            "details": str(e),
            "description": "Error during TLS scan",
            "recommendation": "Verify domain is accessible"
        })
    
    return issues
