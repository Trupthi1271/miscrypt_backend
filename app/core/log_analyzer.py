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
        self.load_logs(log_source)
    
    def load_logs(self, log_source):
        with open(log_source, "r", errors="ignore") as f:
            self.error_logs = f.readlines()
    
    def analyze_logs(self):
        self._detect_tls_handshake_failures()
        '''self._detect_cipher_enumeration(log_lines),
        self._detect_protocol_downgrade(log_lines),
        self._detect_abnormal_connections(log_lines),
        self._detect_ssl_stripping(log_lines),'''
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