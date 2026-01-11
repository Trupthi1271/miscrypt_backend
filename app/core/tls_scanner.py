import ssl, socket,requests

def scan_tls_versions(domain):
    results = {
        "supported_tls_versions": [],
        "weak_tls_detected": False
    }

    tls_versions = {
        "TLS1.0": ssl.TLSVersion.TLSv1,
        "TLS1.1": ssl.TLSVersion.TLSv1_1,
        "TLS1.2": ssl.TLSVersion.TLSv1_2,
        "TLS1.3": ssl.TLSVersion.TLSv1_3
    }

    for name, version in tls_versions.items():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers("DEFAULT:@SECLEVEL=1")

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    results["supported_tls_versions"].append(name)

        except Exception:
            continue

    if any(v in results["supported_tls_versions"] for v in ["TLS1.0", "TLS1.1"]):
        results["weak_tls_detected"] = True

    return results

def scan_cipher_suites(domain):
    results = {
        "supported_cipher_suites": [],
        "weak_cipher_suites": []
    }

    weak_keywords = [
        "RC4",
        "3DES",
        "DES",
        "MD5",
        "SHA1",
        "NULL",
        "EXPORT"
    ]

    cipher_groups = ["HIGH", "MEDIUM", "LOW"]

    for group in cipher_groups:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers(group + ":@SECLEVEL=1")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as s:
                    cipher = s.cipher()
                    if cipher:
                        name = cipher[0]
                        if name not in results["supported_cipher_suites"]:
                            results["supported_cipher_suites"].append(name)

                        for weak in weak_keywords:
                            if weak in name and name not in results["weak_cipher_suites"]:
                                results["weak_cipher_suites"].append(name)

        except:
            pass

    return results

def scan_compression_methods(domain):
    results = {
        "compression_supported": False,
        "compression_method": None,
        "risk": "Safe"
    }

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("DEFAULT:@SECLEVEL=1")

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                comp = ssock.compression()

                if comp:
                    results["compression_supported"] = True
                    results["compression_method"] = comp
                    results["risk"] = "Vulnerable (TLS Compression Enabled)"

    except Exception:
        pass

    return results

def check_certificate_chain(domain):
    results = {
        "valid": True,
        "issues": []
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
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

def full_tls_scan(domain):
    return {
        "tls_versions": scan_tls_versions(domain),
        "cipher_suites": scan_cipher_suites(domain),
        "compression": scan_compression_methods(domain),
        "certificate": check_certificate_chain(domain),
        "hsts": check_hsts(domain),
        "downgrade_protection": check_http_to_https_redirect(domain)
    }
