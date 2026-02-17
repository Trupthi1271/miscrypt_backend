import os
import re
import shutil
import stat
from git import Repo

CLONE_DIR = "temp_repo"


def remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def clone_repo(repo_url: str) -> str:
    if os.path.exists(CLONE_DIR):
        shutil.rmtree(CLONE_DIR, onerror=remove_readonly)

    Repo.clone_from(repo_url, CLONE_DIR)
    return CLONE_DIR


def static_scan(repo_url: str):
    findings = []

    try:
        repo_path = clone_repo(repo_url)

        RULES = [
            ("MD5_HASH_USED", r"\bmd5\s*\(", "HIGH"),
            ("SHA1_HASH_USED", r"\bsha1\s*\(", "HIGH"),
            ("AES_ECB_MODE", r"AES.*ECB", "CRITICAL"),
        ]

        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith((".py", ".java", ".js")):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, "r", errors="ignore") as f:
                            lines = f.readlines()

                        for i, line in enumerate(lines, start=1):
                            for issue, pattern, severity in RULES:
                                if re.search(pattern, line, re.IGNORECASE):
                                    findings.append({
                                        "file": file,
                                        "line": i,
                                        "issue": issue,
                                        "severity": severity
                                    })
                    except:
                        pass

        shutil.rmtree(repo_path, onerror=remove_readonly)
        return findings

    except Exception as e:
        return {
            "error": str(e)
        }
