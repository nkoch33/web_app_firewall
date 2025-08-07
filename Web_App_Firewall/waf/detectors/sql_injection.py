"""
SQL Injection Detector
Detects SQL injection attacks using pattern matching and ML
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Any
from urllib.parse import unquote

from ..utils.logger import get_logger

@dataclass
class SQLInjectionResult:
    """Result of SQL injection detection"""
    is_detected: bool
    reason: str
    confidence: float
    matched_patterns: List[str]
    payload: str

class SQLInjectionDetector:
    """SQL injection detection using pattern matching and ML"""
    
    def __init__(self):
        """Initialize SQL injection detector"""
        self.logger = get_logger(__name__)
        
        # SQL injection patterns
        self.patterns = self._load_sql_patterns()
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'detections': 0,
            'false_positives': 0
        }
    
    def _load_sql_patterns(self) -> List[Dict[str, Any]]:
        """Load SQL injection detection patterns"""
        return [
            # Basic SQL keywords
            {
                'name': 'sql_keywords',
                'pattern': r'\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b',
                'confidence': 0.3,
                'description': 'SQL keywords detected'
            },
            # UNION-based attacks
            {
                'name': 'union_attack',
                'pattern': r'union\s+(all\s+)?select',
                'confidence': 0.8,
                'description': 'UNION-based SQL injection'
            },
            # Comment-based attacks
            {
                'name': 'comment_attack',
                'pattern': r'--|/\*|\*/|#',
                'confidence': 0.6,
                'description': 'SQL comment injection'
            },
            # Boolean-based attacks
            {
                'name': 'boolean_attack',
                'pattern': r'\b(and|or)\s+\d+\s*=\s*\d+',
                'confidence': 0.7,
                'description': 'Boolean-based SQL injection'
            },
            # Time-based attacks
            {
                'name': 'time_attack',
                'pattern': r'sleep\(\d+\)|benchmark\(\d+,.*\)|waitfor\s+delay',
                'confidence': 0.9,
                'description': 'Time-based SQL injection'
            },
            # Error-based attacks
            {
                'name': 'error_attack',
                'pattern': r'convert\(|cast\(|extractvalue\(|updatexml\(',
                'confidence': 0.8,
                'description': 'Error-based SQL injection'
            },
            # Stacked queries
            {
                'name': 'stacked_query',
                'pattern': r';\s*(select|insert|update|delete|drop|create|alter)',
                'confidence': 0.9,
                'description': 'Stacked query SQL injection'
            },
            # Authentication bypass
            {
                'name': 'auth_bypass',
                'pattern': r"'\s+or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?\s*--",
                'confidence': 0.8,
                'description': 'Authentication bypass attempt'
            },
            # Information gathering
            {
                'name': 'info_gathering',
                'pattern': r'@@version|@@hostname|@@datadir|database\(\)|user\(\)',
                'confidence': 0.7,
                'description': 'Information gathering attempt'
            },
            # Advanced evasion techniques
            {
                'name': 'evasion_techniques',
                'pattern': r'/\*.*\*/|--\s*$|#\s*$',
                'confidence': 0.6,
                'description': 'SQL injection evasion technique'
            },
            # Hex encoding
            {
                'name': 'hex_encoding',
                'pattern': r'0x[0-9a-fA-F]+',
                'confidence': 0.5,
                'description': 'Hex-encoded SQL injection'
            },
            # URL encoding
            {
                'name': 'url_encoding',
                'pattern': r'%27|%22|%3d|%3c|%3e|%2d%2d',
                'confidence': 0.4,
                'description': 'URL-encoded SQL injection'
            },
            # Double encoding
            {
                'name': 'double_encoding',
                'pattern': r'%25%37%32|%25%37%31',
                'confidence': 0.6,
                'description': 'Double-encoded SQL injection'
            }
        ]
        
        # Compile patterns
        for pattern in self.patterns:
            pattern['compiled'] = re.compile(pattern['pattern'], re.IGNORECASE)
    
    def detect(self, request_data: Dict[str, Any]) -> SQLInjectionResult:
        """Detect SQL injection in request data"""
        self.stats['total_checks'] += 1
        
        matched_patterns = []
        max_confidence = 0.0
        detected_payload = ""
        
        # Check all data sources
        data_sources = [
            ('url', request_data.get('url', '')),
            ('args', str(request_data.get('args', ''))),
            ('form', str(request_data.get('form', ''))),
            ('json', str(request_data.get('json', ''))),
            ('headers', str(request_data.get('headers', '')))
        ]
        
        for source_name, data in data_sources:
            # URL decode the data
            decoded_data = unquote(data)
            
            # Check each pattern
            for pattern in self.patterns:
                if pattern['compiled'].search(decoded_data):
                    matched_patterns.append(pattern['name'])
                    
                    if pattern['confidence'] > max_confidence:
                        max_confidence = pattern['confidence']
                        detected_payload = decoded_data
                    
                    self.logger.debug(f"SQL injection pattern '{pattern['name']}' matched in {source_name}")
        
        # Determine if SQL injection is detected
        is_detected = len(matched_patterns) > 0 and max_confidence > 0.5
        
        if is_detected:
            self.stats['detections'] += 1
            reason = f"SQL injection detected: {', '.join(matched_patterns)}"
        else:
            reason = ""
        
        return SQLInjectionResult(
            is_detected=is_detected,
            reason=reason,
            confidence=max_confidence,
            matched_patterns=matched_patterns,
            payload=detected_payload[:200] if detected_payload else ""  # Limit payload length
        )
    
    def add_custom_pattern(self, name: str, pattern: str, confidence: float, description: str):
        """Add a custom SQL injection pattern"""
        try:
            new_pattern = {
                'name': name,
                'pattern': pattern,
                'confidence': confidence,
                'description': description,
                'compiled': re.compile(pattern, re.IGNORECASE)
            }
            
            self.patterns.append(new_pattern)
            self.logger.info(f"Added custom SQL injection pattern: {name}")
            
        except Exception as e:
            self.logger.error(f"Error adding custom pattern {name}: {str(e)}")
    
    def remove_pattern(self, pattern_name: str):
        """Remove a pattern by name"""
        self.patterns = [p for p in self.patterns if p['name'] != pattern_name]
        self.logger.info(f"Removed SQL injection pattern: {pattern_name}")
    
    def get_patterns(self) -> List[Dict[str, Any]]:
        """Get all SQL injection patterns"""
        return [
            {
                'name': pattern['name'],
                'pattern': pattern['pattern'],
                'confidence': pattern['confidence'],
                'description': pattern['description']
            }
            for pattern in self.patterns
        ]
    
    def test_payload(self, payload: str) -> SQLInjectionResult:
        """Test a specific payload for SQL injection"""
        test_data = {
            'url': payload,
            'args': {},
            'form': {},
            'json': {},
            'headers': {}
        }
        
        return self.detect(test_data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get SQL injection detector statistics"""
        return {
            **self.stats,
            'total_patterns': len(self.patterns),
            'detection_rate': self.stats['detections'] / max(1, self.stats['total_checks'])
        }
    
    def update_pattern_confidence(self, pattern_name: str, new_confidence: float):
        """Update confidence level for a pattern"""
        for pattern in self.patterns:
            if pattern['name'] == pattern_name:
                pattern['confidence'] = new_confidence
                self.logger.info(f"Updated confidence for pattern {pattern_name}: {new_confidence}")
                return
        
        self.logger.warning(f"Pattern not found: {pattern_name}")
    
    def analyze_entropy(self, text: str) -> float:
        """Analyze entropy of text to detect encoded SQL injection"""
        if not text:
            return 0.0
        
        # Calculate character frequency
        char_count = {}
        for char in text:
            char_count[char] = char_count.get(char, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        
        for count in char_count.values():
            p = count / length
            if p > 0:
                entropy -= p * (p.bit_length() - 1)  # Simplified entropy
        
        return entropy
    
    def detect_encoded_injection(self, text: str) -> bool:
        """Detect encoded SQL injection attempts"""
        # Check for common encoding patterns
        encoded_patterns = [
            r'%27',  # URL-encoded single quote
            r'%22',  # URL-encoded double quote
            r'%3d',  # URL-encoded equals
            r'%3c',  # URL-encoded less than
            r'%3e',  # URL-encoded greater than
            r'0x[0-9a-fA-F]+',  # Hex encoding
            r'\\x[0-9a-fA-F]+',  # Hex encoding with backslash
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
        ]
        
        for pattern in encoded_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False 