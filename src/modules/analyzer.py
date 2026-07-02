# src/modules/analyzer.py
# Traffic Analyzer Module - NETER·SKOPOS

import re
from typing import Dict, List, Tuple, Optional
from datetime import datetime

class TrafficAnalyzer:
    def __init__(self):
        self.sensitive_patterns = {
            'password': r'(password|passwd|pwd|secret|api[_-]?key|apikey|private[_-]?key)',
            'username': r'(username|user[_-]?name|email|mail|userid|uid|login|account)',
            'token': r'(token|bearer|jwt|access[_-]?token|refresh[_-]?token|auth[_-]?token)',
            'pii': r'(ssn|social|phone|mobile|address|birth|name|zip)',
            'financial': r'(credit[_-]?card|cvv|cvc|bank|routing|iban|swift)',
            'auth': r'(auth|cookie|session|sessid|jsessionid|phpsessid)',
            'jwt': r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
            'aws': r'(AKIA[A-Z0-9]{16})'
        }

        self.severity_map = {
            'password': 'CRITICAL',
            'token': 'CRITICAL',
            'jwt': 'CRITICAL',
            'aws': 'CRITICAL',
            'auth': 'HIGH',
            'financial': 'HIGH',
            'pii': 'MEDIUM',
            'username': 'MEDIUM'
        }

    def extract_credentials(self, data: str, source: str, url: str = "", host: str = "") -> List[Dict]:
        credentials = []
        if not data:
            return credentials

        # JWT detection
        jwt_matches = re.finditer(self.sensitive_patterns['jwt'], data)
        for match in jwt_matches:
            credentials.append({
                'type': 'jwt',
                'key': 'JWT_TOKEN',
                'value': match.group(0)[:100] + '...',
                'source': source,
                'context': f"JWT found in {source}",
                'url': url,
                'host': host,
                'severity': 'CRITICAL'
            })

        # AWS key detection
        aws_matches = re.finditer(self.sensitive_patterns['aws'], data)
        for match in aws_matches:
            credentials.append({
                'type': 'aws_key',
                'key': 'AWS_ACCESS_KEY',
                'value': match.group(0),
                'source': source,
                'context': f"AWS key found in {source}",
                'url': url,
                'host': host,
                'severity': 'CRITICAL'
            })

        # General pattern search
        for cred_type, pattern in self.sensitive_patterns.items():
            if cred_type in ['jwt', 'aws']:
                continue
            matches = re.finditer(pattern, data, re.IGNORECASE)
            for match in matches:
                start = max(0, match.start() - 40)
                end = min(len(data), match.end() + 80)
                context = data[start:end]
                value_match = re.search(r'[=:\s]+([^\s&;,]+)', context[match.end():])
                if value_match:
                    value = value_match.group(1).strip()
                    if len(value) > 2 and value not in ['0', '1', 'true', 'false', 'null']:
                        credentials.append({
                            'type': cred_type,
                            'key': match.group(0),
                            'value': value[:100],
                            'source': source,
                            'context': context[:200],
                            'url': url,
                            'host': host,
                            'severity': self.severity_map.get(cred_type, 'MEDIUM')
                        })
        return credentials

    def calculate_risk(self, session_data: Dict) -> Tuple[str, int, List[str]]:
        risk_score = 0
        findings = []

        if session_data.get('credentials'):
            for cred in session_data['credentials']:
                severity = cred.get('severity', 'MEDIUM')
                if severity == 'CRITICAL':
                    risk_score += 15
                    findings.append(f"CRITICAL: {cred.get('type')} exposed")
                elif severity == 'HIGH':
                    risk_score += 10
                    findings.append(f"HIGH: {cred.get('type')} exposed")
                else:
                    risk_score += 5

        if session_data.get('plaintext'):
            risk_score += len(session_data['plaintext']) * 5
            findings.append(f"{len(session_data['plaintext'])} plaintext HTTP requests")

        if session_data.get('cookies'):
            weak = [c for c in session_data['cookies'] if not c.get('secure', False)]
            if weak:
                risk_score += len(weak) * 3
                findings.append(f"{len(weak)} cookies missing Secure flag")

        if session_data.get('total_requests', 0) > 100:
            risk_score += 5

        if risk_score >= 60:
            return "CRITICAL", min(risk_score, 100), findings
        elif risk_score >= 40:
            return "HIGH", min(risk_score, 100), findings
        elif risk_score >= 20:
            return "MEDIUM", min(risk_score, 100), findings
        else:
            return "LOW", min(risk_score, 100), findings