import ssl
import socket
import requests

# -------------------- TLS VERSION SCAN --------------------
import subprocess

def scan_tls_versions(domain, port=443):
    results = {
        "supported_tls_versions": [],
        "weak_tls_detected": False
    }

    tls_versions = {
        "TLS1.0": "tls1",
        "TLS1.1": "tls1_1",
        "TLS1.2": "tls1_2",
        "TLS1.3": "tls1_3"
    }

    for name, openssl_flag in tls_versions.items():
        try:
            cmd = [
                "openssl", "s_client",
                "-connect", f"{domain}:{port}",
                f"-{openssl_flag}",
                "-servername", domain
            ]
            # Run openssl, suppress stdout except handshake info
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, text=True
            )
            output = proc.stdout + proc.stderr

            # Check if handshake succeeded
            if "Verify return code: 0 (ok)" in output or "SSL handshake has read" in output:
                results["supported_tls_versions"].append(name)

        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    if any(v in results["supported_tls_versions"] for v in ["TLS1.0", "TLS1.1"]):
        results["weak_tls_detected"] = True

    return results

# -------------------- CIPHER SUITE SCAN --------------------
def scan_cipher_suites(domain, port=443):
    results = {
        "supported_cipher_suites": [],
        "weak_cipher_suites": []
    }

    weak_keywords = ["RC4", "3DES", "DES", "MD5", "SHA1", "NULL", "EXPORT"]

    # Test all weak ciphers individually
    for cipher in weak_keywords:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher + ":@SECLEVEL=0")  # Force low security

            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher_name = ssock.cipher()[0]
                    if cipher_name not in results["supported_cipher_suites"]:
                        results["supported_cipher_suites"].append(cipher_name)
                    if cipher_name not in results["weak_cipher_suites"]:
                        results["weak_cipher_suites"].append(cipher_name)

        except Exception:
            continue

    return results

# -------------------- TLS COMPRESSION SCAN --------------------
def scan_compression_methods(domain, port=443):
    results = {
        "compression_supported": False,
        "compression_method": None,
        "risk": "Safe"
    }

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")

        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                comp = ssock.compression()
                if comp:
                    results["compression_supported"] = True
                    results["compression_method"] = comp
                    results["risk"] = "Vulnerable (TLS Compression Enabled)"

    except Exception:
        pass

    return results

# -------------------- CERTIFICATE CHECK --------------------
def check_certificate_chain(domain, port=443):
    results = {
        "valid": True,
        "issues": []
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    results["valid"] = False
                    results["issues"].append("No certificate presented")

    except ssl.SSLCertVerificationError as e:
        results["valid"] = False
        results["issues"].append(str(e))

    except Exception as e:
        results["valid"] = False
        results["issues"].append(str(e))

    return results

# -------------------- HSTS CHECK --------------------
def check_hsts(domain):
    results = {
        "hsts_present": False,
        "risk": "Vulnerable"
    }

    try:
        r = requests.get("https://" + domain, timeout=5)
        if "strict-transport-security" in r.headers:
            results["hsts_present"] = True
            results["risk"] = "Safe"
    except:
        pass

    return results

# -------------------- HTTP TO HTTPS REDIRECT --------------------
def check_http_to_https_redirect(domain):
    results = {
        "redirects_to_https": False,
        "risk": "Vulnerable"
    }

    try:
        r = requests.get("http://" + domain, allow_redirects=False, timeout=5)
        if r.status_code in [301, 302] and "https://" in r.headers.get("Location", ""):
            results["redirects_to_https"] = True
            results["risk"] = "Safe"
    except:
        pass

    return results

# -------------------- FULL TLS SCAN --------------------
def full_tls_scan(domain, port=443):
    return {
        "tls_versions": scan_tls_versions(domain, port),
        "cipher_suites": scan_cipher_suites(domain, port),
        "compression": scan_compression_methods(domain, port),
        "certificate": check_certificate_chain(domain, port),
        "hsts": check_hsts(domain),
        "downgrade_protection": check_http_to_https_redirect(domain)
    }

# -------------------- MAIN --------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python tls_scanner.py <domain> [port]")
        sys.exit(1)

    domain = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print("\n================ TLS SECURITY SCAN ================\n")
    results = full_tls_scan(domain, port)

    print("--- TLS_VERSIONS ---")
    print(results["tls_versions"])
    print("\n--- CIPHER_SUITES ---")
    print(results["cipher_suites"])
    print("\n--- COMPRESSION ---")
    print(results["compression"])
    print("\n--- CERTIFICATE ---")
    print(results["certificate"])
    print("\n--- HSTS ---")
    print(results["hsts"])
    print("\n--- HTTP_TO_HTTPS_REDIRECT ---")
    print(results["downgrade_protection"])
    print("\n=============== SCAN COMPLETE ===============\n")
