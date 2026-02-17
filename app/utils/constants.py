# Cryptographic constants for detection

WEAK_ALGORITHMS = [
    'DES', 'RC4', '3DES', 'ARCFOUR', 'BLOWFISH'
]

WEAK_HASHES = [
    'MD5', 'SHA1', 'MD4', 'MD2'
]

INSECURE_PATTERNS = {
    'ECB_MODE': r'AES\.MODE_ECB|mode.*=.*ECB',
    'HARDCODED_SECRET': r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
    'WEAK_RSA': r'RSA.*1024|key_size.*=.*1024',
    'INSECURE_RANDOM': r'random\.random\(|Math\.random\('
}

SEVERITY_LEVELS = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1
}
