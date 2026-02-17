#!/usr/bin/env python3
"""
TLS Log Dataset Generator for MisCrypt Module 3 Testing
Generates realistic nginx/apache logs with TLS attack patterns
"""

import random
from datetime import datetime, timedelta
from typing import List, Dict
import ipaddress

class TLSLogGenerator:
    def __init__(self):
        # Attack source IPs (simulated attackers)
        self.attacker_ips = [
            "192.168.1.100", "10.0.0.50", "172.16.0.25", 
            "203.0.113.15", "198.51.100.42"
        ]
        
        # Legitimate user IPs
        self.legitimate_ips = [
            "192.168.1.10", "192.168.1.20", "10.0.0.5",
            "172.16.0.10", "203.0.113.100"
        ]
        
        # User agents
        self.legitimate_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        
        self.attack_agents = [
            "curl/7.68.0", "python-requests/2.25.1", "nmap", 
            "OpenSSL/1.1.1", "sslscan", "testssl.sh"
        ]
        
        # TLS configurations
        self.weak_protocols = ["TLSv1", "TLSv1.1", "SSLv3"]
        self.strong_protocols = ["TLSv1.2", "TLSv1.3"]
        
        self.weak_ciphers = [
            "RC4-SHA", "DES-CBC3-SHA", "AES128-SHA", 
            "ECDHE-RSA-RC4-SHA", "DHE-RSA-DES-CBC3-SHA"
        ]
        
        self.strong_ciphers = [
            "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-CHACHA20-POLY1305", "AES256-GCM-SHA384"
        ]

    def generate_timestamp(self, base_time: datetime, offset_minutes: int = 0) -> str:
        """Generate nginx-style timestamp"""
        time = base_time + timedelta(minutes=offset_minutes)
        return time.strftime("%d/%b/%Y:%H:%M:%S %z")

    def generate_legitimate_traffic(self, count: int, base_time: datetime) -> List[str]:
        """Generate normal HTTPS traffic logs"""
        logs = []
        
        for i in range(count):
            ip = random.choice(self.legitimate_ips)
            agent = random.choice(self.legitimate_agents)
            protocol = random.choice(self.strong_protocols)
            cipher = random.choice(self.strong_ciphers)
            timestamp = self.generate_timestamp(base_time, i)
            
            # Normal successful HTTPS requests
            paths = ["/", "/login", "/dashboard", "/api/data", "/images/logo.png"]
            path = random.choice(paths)
            status = random.choice([200, 200, 200, 304, 404])  # Mostly successful
            
            log = f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} {random.randint(500, 5000)} "-" "{agent}" ssl_protocol={protocol} ssl_cipher={cipher} ssl_session_reused=.'
            logs.append(log)
            
        return logs

    def generate_tls_handshake_failures(self, count: int, base_time: datetime) -> List[str]:
        """Generate TLS handshake failure patterns (AttackType.TLS_HANDSHAKE_FAILURE)"""
        logs = []
        
        for i in range(count):
            ip = random.choice(self.attacker_ips)
            agent = random.choice(self.attack_agents)
            timestamp = self.generate_timestamp(base_time, i * 2)
            
            # Failed TLS handshakes - no protocol/cipher logged
            log = f'{ip} - - [{timestamp}] "GET / HTTP/1.1" 400 0 "-" "{agent}" ssl_protocol=- ssl_cipher=- ssl_session_reused=-'
            logs.append(log)
            
        return logs

    def generate_cipher_enumeration(self, count: int, base_time: datetime) -> List[str]:
        """Generate cipher enumeration attack patterns (AttackType.CIPHER_ENUMERATION)"""
        logs = []
        attacker_ip = random.choice(self.attacker_ips)
        
        for i in range(count):
            agent = "sslscan/2.0.0"
            timestamp = self.generate_timestamp(base_time, i)
            
            # Rapid requests testing different ciphers
            if i < count // 2:
                # Testing weak ciphers (some succeed)
                cipher = random.choice(self.weak_ciphers)
                protocol = random.choice(self.weak_protocols)
                status = 200 if random.random() > 0.3 else 400
                ssl_proto = protocol if status == 200 else "-"
                ssl_cipher = cipher if status == 200 else "-"
            else:
                # Testing strong ciphers (mostly fail on misconfigured server)
                cipher = random.choice(self.strong_ciphers)
                protocol = random.choice(self.strong_protocols)
                status = 400
                ssl_proto = "-"
                ssl_cipher = "-"
            
            log = f'{attacker_ip} - - [{timestamp}] "GET / HTTP/1.1" {status} {random.randint(0, 500)} "-" "{agent}" ssl_protocol={ssl_proto} ssl_cipher={ssl_cipher} ssl_session_reused=-'
            logs.append(log)
            
        return logs

    def generate_protocol_downgrade(self, count: int, base_time: datetime) -> List[str]:
        """Generate protocol downgrade attack patterns (AttackType.PROTOCOL_DOWNGRADE)"""
        logs = []
        attacker_ip = random.choice(self.attacker_ips)
        
        for i in range(count):
            agent = "testssl.sh/3.0.5"
            timestamp = self.generate_timestamp(base_time, i)
            
            # Sequence: Try TLS 1.3 -> 1.2 -> 1.1 -> 1.0 -> SSLv3
            protocols = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"]
            protocol = protocols[i % len(protocols)]
            
            # Older protocols might succeed on misconfigured server
            if protocol in ["TLSv1", "TLSv1.1", "SSLv3"]:
                status = 200 if random.random() > 0.5 else 400
                ssl_proto = protocol if status == 200 else "-"
                ssl_cipher = random.choice(self.weak_ciphers) if status == 200 else "-"
            else:
                status = 400  # Modern protocols rejected
                ssl_proto = "-"
                ssl_cipher = "-"
            
            log = f'{attacker_ip} - - [{timestamp}] "GET / HTTP/1.1" {status} {random.randint(0, 500)} "-" "{agent}" ssl_protocol={ssl_proto} ssl_cipher={ssl_cipher} ssl_session_reused=-'
            logs.append(log)
            
        return logs

    def generate_ssl_stripping_attempts(self, count: int, base_time: datetime) -> List[str]:
        """Generate SSL stripping attack patterns (AttackType.SSL_STRIPPING)"""
        logs = []
        attacker_ip = random.choice(self.attacker_ips)
        
        for i in range(count):
            agent = "curl/7.68.0"
            timestamp = self.generate_timestamp(base_time, i)
            
            # HTTP requests to HTTPS endpoints (redirect attempts)
            paths = ["/login", "/admin", "/secure", "/payment"]
            path = random.choice(paths)
            
            # These would be HTTP requests that get redirected to HTTPS
            log = f'{attacker_ip} - - [{timestamp}] "GET {path} HTTP/1.1" 301 0 "-" "{agent}" ssl_protocol=- ssl_cipher=- ssl_session_reused=-'
            logs.append(log)
            
        return logs

    def generate_certificate_probing(self, count: int, base_time: datetime) -> List[str]:
        """Generate certificate probing patterns (AttackType.CERTIFICATE_PROBING)"""
        logs = []
        attacker_ip = random.choice(self.attacker_ips)
        
        for i in range(count):
            agent = "OpenSSL/1.1.1"
            timestamp = self.generate_timestamp(base_time, i)
            
            # Requests that complete handshake but probe certificate details
            protocol = random.choice(self.strong_protocols)
            cipher = random.choice(self.strong_ciphers)
            
            # Quick connections that immediately disconnect (cert probing)
            log = f'{attacker_ip} - - [{timestamp}] "GET / HTTP/1.1" 200 0 "-" "{agent}" ssl_protocol={protocol} ssl_cipher={cipher} ssl_session_reused=.'
            logs.append(log)
            
        return logs

    def generate_error_logs(self, base_time: datetime) -> List[str]:
        """Generate nginx error logs with TLS-specific errors"""
        errors = []
        
        error_patterns = [
            "SSL_do_handshake() failed (SSL: error:1408F10B:SSL routines:ssl3_get_record:wrong version number)",
            "SSL handshake failed: unsupported protocol",
            "SSL_accept() failed (SSL: error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure)",
            "SSL_do_handshake() failed (SSL: error:140943FC:SSL routines:ssl3_read_bytes:sslv3 alert bad record mac)",
            "SSL certificate verify failed: certificate has expired",
            "SSL_CTX_use_certificate() failed (SSL: error:0906D06C:PEM routines:PEM_read_bio:no start line)",
        ]
        
        for i, pattern in enumerate(error_patterns * 3):  # Repeat patterns
            timestamp = self.generate_timestamp(base_time, i * 5)
            attacker_ip = random.choice(self.attacker_ips)
            
            error = f'{timestamp.replace("[", "").replace("]", "")} [error] 1234#0: *{i+1} {pattern}, client: {attacker_ip}, server: example.com, request: "GET / HTTP/1.1", host: "example.com"'
            errors.append(error)
            
        return errors

    def generate_complete_dataset(self, output_dir: str = "sample_logs"):
        """Generate complete dataset with all attack patterns"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        base_time = datetime.now().replace(tzinfo=None)
        
        # Generate access logs
        access_logs = []
        
        # Normal traffic (baseline)
        access_logs.extend(self.generate_legitimate_traffic(50, base_time))
        
        # Attack patterns
        access_logs.extend(self.generate_tls_handshake_failures(15, base_time + timedelta(hours=1)))
        access_logs.extend(self.generate_cipher_enumeration(20, base_time + timedelta(hours=2)))
        access_logs.extend(self.generate_protocol_downgrade(10, base_time + timedelta(hours=3)))
        access_logs.extend(self.generate_ssl_stripping_attempts(8, base_time + timedelta(hours=4)))
        access_logs.extend(self.generate_certificate_probing(12, base_time + timedelta(hours=5)))
        
        # More normal traffic mixed in
        access_logs.extend(self.generate_legitimate_traffic(30, base_time + timedelta(hours=6)))
        
        # Sort by timestamp
        access_logs.sort()
        
        # Write access logs
        with open(f"{output_dir}/nginx_access.log", "w") as f:
            f.write("\n".join(access_logs))
        
        # Generate error logs
        error_logs = self.generate_error_logs(base_time)
        
        with open(f"{output_dir}/nginx_error.log", "w") as f:
            f.write("\n".join(error_logs))
        
        print(f"Generated dataset in {output_dir}/")
        print(f"- nginx_access.log: {len(access_logs)} entries")
        print(f"- nginx_error.log: {len(error_logs)} entries")
        print("\nAttack patterns included:")
        print("- TLS handshake failures")
        print("- Cipher enumeration attacks")
        print("- Protocol downgrade attempts")
        print("- SSL stripping attempts")
        print("- Certificate probing")

if __name__ == "__main__":
    generator = TLSLogGenerator()
    generator.generate_complete_dataset()