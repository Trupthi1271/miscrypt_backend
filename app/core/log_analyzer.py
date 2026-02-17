import re 
from collections import defaultdict
from datetime import datetime

TLS_HANDSHAKE_FAILURE = "tls_handshake_failure"
CIPHER_ENUMERATION = "cipher_enumeration"
PROTOCOL_DOWNGRADE = "protocol_downgrade"
ABNORMAL_CONNECTION = "abnormal_connection"
SSL_STRIPPING = "ssl_stripping"
CERTIFICATE_PROBING = "certificate_probing"

class log_analyzer:
    def __init__(self, log_source):
        self.findings = defaultdict(list)
        self.error_logs = []
        self.access_logs = []
        self.load_logs(log_source)
    
    def load_logs(self, log_source):
        with open(log_source, "r", errors="ignore") as f:
            lines = f.readlines()
            # Separate error and access logs based on content
            for line in lines:
                if any(keyword in line.lower() for keyword in ["error", "failed", "ssl", "tls"]):
                    self.error_logs.append(line)
                else:
                    self.access_logs.append(line)
    
    def analyze_logs(self):
        self._detect_tls_handshake_failures()
        self._detect_cipher_enumeration()
        self._detect_protocol_downgrade()
        self._detect_abnormal_connections()
        self._detect_ssl_stripping()
        self._detect_certificate_probing()
        
        return self._format_results()
    
    def _detect_tls_handshake_failures(self):
        pattern = re.compile(r"SSL_do_handshake\(\) failed|tls handshake failed", re.IGNORECASE)
        for line in self.error_logs:
            if pattern.search(line):
                self.findings[TLS_HANDSHAKE_FAILURE].append(line.strip())
    
    def _detect_certificate_probing(self):
        pattern = re.compile(r"certificate verify failed|unknown ca|bad certificate", re.IGNORECASE)
        for line in self.error_logs:
            if pattern.search(line):
                self.findings[CERTIFICATE_PROBING].append(line.strip())
    
    def _detect_cipher_enumeration(self):
        ip_counter = defaultdict(int)
        ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        for line in self.error_logs:
            if "handshake" in line.lower():
                ip_match = ip_pattern.search(line)
                if ip_match:
                    ip_counter[ip_match.group()] += 1
        for ip, count in ip_counter.items():
            if count >= 5:
                self.findings[CIPHER_ENUMERATION].append(
                     f"Possible cipher enumeration from IP {ip} ({count} failed handshakes)"
                )
    
    def _detect_protocol_downgrade(self):
        for line in self.error_logs:
            if "http/1.0" in line.lower() or "protocol" in line.lower():
                self.findings[PROTOCOL_DOWNGRADE].append(line.strip())
    
    def _detect_ssl_stripping(self):
        for line in self.access_logs:
            if "GET /" in line and "http://" in line:
                self.findings[SSL_STRIPPING].append(line.strip())
    
    def _detect_abnormal_connections(self):
        ip_hits = defaultdict(int)
        ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

        for line in self.access_logs:
            ip_match = ip_pattern.search(line)
            if ip_match:
                ip_hits[ip_match.group()] += 1

        for ip, count in ip_hits.items():
            if count > 100:
                self.findings[ABNORMAL_CONNECTION].append(
                    f"High request volume from IP {ip} ({count} requests)"
                )

    def _format_results(self):
        results = []
        for threat, evidence in self.findings.items():
            results.append({
                "threat_type": threat,
                "detected": len(evidence) > 0,
                "evidence_count": len(evidence),
                "samples": evidence[:5]  
            })
        return results