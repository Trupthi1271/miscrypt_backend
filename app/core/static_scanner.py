import requests

def static_scan(url: str):
    result = {
        "url": url,
        "reachable": False,
        "https": False,
        "http_to_https": False,
        "missing_headers": []
    }

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        result["reachable"] = True

        # HTTPS check
        if response.url.startswith("https://"):
            result["https"] = True

        # HTTP → HTTPS redirect check
        if url.startswith("http://") and response.url.startswith("https://"):
            result["http_to_https"] = True

        # Security headers
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"
        ]

        for header in security_headers:
            if header not in response.headers:
                result["missing_headers"].append(header)

    except Exception as e:
        result["error"] = str(e)

    return result
