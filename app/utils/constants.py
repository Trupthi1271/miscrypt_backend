# app/utils/constants.py

# --- Weak crypto definitions ---
WEAK_HASHES = ["MD5", "SHA1"]
MIN_RSA_KEY_SIZE = 2048
DISALLOWED_AES_MODES = ["ECB"]

# --- Weak TLS definitions ---
WEAK_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]
WEAK_CIPHERS = [
    "RC4",
    "DES",
    "3DES"
]

# --- Risk scoring weights (used later) ---
STATIC_WEIGHT = 3
TLS_WEIGHT = 3
RUNTIME_WEIGHT = 4
