import os
import re
import shutil
import stat
from git import Repo

CLONE_DIR = "temp_repo"

def remove_readonly(func, path, _):
    """Helper to remove read-only files on Windows"""
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clone_repo(repo_url: str) -> str:
    """Clone a Git repository"""
    if os.path.exists(CLONE_DIR):
        shutil.rmtree(CLONE_DIR, onerror=remove_readonly)
    Repo.clone_from(repo_url, CLONE_DIR)
    return CLONE_DIR

def run_static_scan(code: str, language: str = "python"):
    """
    Scan source code for cryptographic misconfigurations
    """
    findings = []
    lines = code.split('\n')
    
    # Check for weak hash functions
    for i, line in enumerate(lines, 1):
        # MD5 usage
        if re.search(r'md5|MD5|hashlib\.md5', line, re.IGNORECASE):
            findings.append({
                "line": i,
                "code": line.strip(),
                "issue": "Weak Hash Function: MD5",
                "severity": "HIGH",
                "description": "MD5 is cryptographically broken and should not be used",
                "recommendation": "Use SHA-256 or SHA-3 instead"
            })
        
        # SHA1 usage
        if re.search(r'sha1|SHA1|hashlib\.sha1', line, re.IGNORECASE):
            findings.append({
                "line": i,
                "code": line.strip(),
                "issue": "Weak Hash Function: SHA1",
                "severity": "HIGH",
                "description": "SHA1 is deprecated and vulnerable to collision attacks",
                "recommendation": "Use SHA-256 or SHA-3 instead"
            })
        
        # ECB mode detection
        if re.search(r'AES\.MODE_ECB|mode.*=.*ECB|"ECB"', line, re.IGNORECASE):
            findings.append({
                "line": i,
                "code": line.strip(),
                "issue": "Insecure Cipher Mode: ECB",
                "severity": "CRITICAL",
                "description": "ECB mode leaks data patterns and is not semantically secure",
                "recommendation": "Use CBC, GCM, or CTR mode instead"
            })
        
        # Hardcoded secrets
        if re.search(r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
            findings.append({
                "line": i,
                "code": line.strip(),
                "issue": "Hardcoded Secret",
                "severity": "CRITICAL",
                "description": "Hardcoded credentials found in source code",
                "recommendation": "Use environment variables or secure key management"
            })
        
        # Weak RSA key size
        if re.search(r'RSA.*1024|key_size.*=.*1024', line):
            findings.append({
                "line": i,
                "code": line.strip(),
                "issue": "Weak RSA Key Size",
                "severity": "HIGH",
                "description": "RSA key size less than 2048 bits is considered weak",
                "recommendation": "Use at least 2048-bit RSA keys"
            })
        
        # Insecure random
        if re.search(r'random\.random\(|Math\.random\(', line):
            findings.append({
                "line": i,
                "code": line.strip(),
                "issue": "Insecure Random Number Generation",
                "severity": "MEDIUM",
                "description": "Using non-cryptographic random number generator",
                "recommendation": "Use secrets module (Python) or crypto.getRandomValues (JS)"
            })
    
    return findings

def scan_git_repository(repo_url: str):
    """
    Clone and scan a Git repository for cryptographic issues
    """
    findings = []
    
    try:
        repo_path = clone_repo(repo_url)
        
        # Detection rules
        RULES = [
            ("Weak Hash Function: MD5", r'\bmd5\s*\(|hashlib\.md5|MD5', "HIGH"),
            ("Weak Hash Function: SHA1", r'\bsha1\s*\(|hashlib\.sha1|SHA1', "HIGH"),
            ("Insecure Cipher Mode: ECB", r'AES\.MODE_ECB|mode.*=.*ECB|"ECB"', "CRITICAL"),
            ("Hardcoded Secret", r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']', "CRITICAL"),
            ("Weak RSA Key", r'RSA.*1024|key_size.*=.*1024', "HIGH"),
            ("Insecure Random", r'random\.random\(|Math\.random\(', "MEDIUM"),
        ]
        
        # Scan all code files
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith((".py", ".java", ".js", ".ts", ".go")):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, repo_path)
                    
                    try:
                        with open(file_path, "r", errors="ignore") as f:
                            lines = f.readlines()
                        
                        for i, line in enumerate(lines, start=1):
                            for issue, pattern, severity in RULES:
                                if re.search(pattern, line, re.IGNORECASE):
                                    findings.append({
                                        "file": relative_path,
                                        "line": i,
                                        "code": line.strip(),
                                        "issue": issue,
                                        "severity": severity,
                                        "description": f"Found in {relative_path}",
                                        "recommendation": get_recommendation(issue)
                                    })
                    except Exception as e:
                        pass
        
        # Cleanup
        shutil.rmtree(repo_path, onerror=remove_readonly)
        
        return findings
        
    except Exception as e:
        raise Exception(f"Failed to scan repository: {str(e)}")

def get_recommendation(issue: str) -> str:
    """Get recommendation based on issue type"""
    recommendations = {
        "Weak Hash Function: MD5": "Use SHA-256 or SHA-3 instead",
        "Weak Hash Function: SHA1": "Use SHA-256 or SHA-3 instead",
        "Insecure Cipher Mode: ECB": "Use CBC, GCM, or CTR mode instead",
        "Hardcoded Secret": "Use environment variables or secure key management",
        "Weak RSA Key": "Use at least 2048-bit RSA keys",
        "Insecure Random": "Use secrets module (Python) or crypto.getRandomValues (JS)"
    }
    return recommendations.get(issue, "Review and fix this security issue")
