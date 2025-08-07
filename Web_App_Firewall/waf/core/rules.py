"""
WAF Rule Engine
Handles custom security rules and pattern matching
"""

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from flask import Request

from ..utils.logger import get_logger

@dataclass
class RuleResult:
    """Result of rule analysis"""
    is_blocked: bool
    reason: str
    threat_score: float
    detected_threats: List[str]
    matched_rule: Optional[str] = None

class RuleEngine:
    """Rule-based security engine"""
    
    def __init__(self):
        """Initialize rule engine with default rules"""
        self.logger = get_logger(__name__)
        self.rules = []
        self.stats = {
            'total_checks': 0,
            'rules_matched': 0,
            'blocks': 0
        }
        
        # Load default rules
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default security rules"""
        default_rules = [
            # Path traversal attacks
            {
                'name': 'path_traversal',
                'pattern': r'\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c',
                'action': 'block',
                'severity': 'high',
                'description': 'Path traversal attack detected'
            },
            # Command injection
            {
                'name': 'command_injection',
                'pattern': r'[;&|`]|%3b|%7c|%60',
                'action': 'block',
                'severity': 'high',
                'description': 'Command injection attempt detected'
            },
            # File inclusion
            {
                'name': 'file_inclusion',
                'pattern': r'include\(|require\(|include_once\(|require_once\(',
                'action': 'block',
                'severity': 'high',
                'description': 'File inclusion attack detected'
            },
            # Directory traversal
            {
                'name': 'directory_traversal',
                'pattern': r'\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c',
                'action': 'block',
                'severity': 'high',
                'description': 'Directory traversal attack detected'
            },
            # PHP code injection
            {
                'name': 'php_injection',
                'pattern': r'<\?php|<\?=|<\?',
                'action': 'block',
                'severity': 'high',
                'description': 'PHP code injection attempt detected'
            },
            # JavaScript injection
            {
                'name': 'js_injection',
                'pattern': r'<script|javascript:|on\w+\s*=',
                'action': 'block',
                'severity': 'medium',
                'description': 'JavaScript injection attempt detected'
            },
            # SQL keywords (basic)
            {
                'name': 'sql_keywords',
                'pattern': r'\b(union|select|insert|update|delete|drop|create|alter)\b',
                'action': 'log',
                'severity': 'medium',
                'description': 'SQL keywords detected'
            },
            # Suspicious user agents
            {
                'name': 'suspicious_user_agent',
                'pattern': r'(sqlmap|nikto|nmap|wget|curl)',
                'action': 'log',
                'severity': 'medium',
                'description': 'Suspicious user agent detected'
            },
            # Large payloads
            {
                'name': 'large_payload',
                'pattern': r'.{10000,}',
                'action': 'log',
                'severity': 'low',
                'description': 'Large payload detected'
            }
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: Dict[str, Any]):
        """Add a custom rule"""
        try:
            # Validate rule
            required_fields = ['name', 'pattern', 'action', 'severity']
            for field in required_fields:
                if field not in rule:
                    raise ValueError(f"Missing required field: {field}")
            
            # Compile regex pattern
            rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE)
            
            # Add rule
            self.rules.append(rule)
            self.logger.info(f"Added rule: {rule['name']}")
            
        except Exception as e:
            self.logger.error(f"Error adding rule {rule.get('name', 'unnamed')}: {str(e)}")
    
    def remove_rule(self, rule_name: str):
        """Remove a rule by name"""
        self.rules = [rule for rule in self.rules if rule['name'] != rule_name]
        self.logger.info(f"Removed rule: {rule_name}")
    
    def analyze_request(self, request_data: Dict[str, Any]) -> RuleResult:
        """Analyze request against all rules"""
        self.stats['total_checks'] += 1
        
        detected_threats = []
        threat_score = 0.0
        matched_rule = None
        is_blocked = False
        reason = ""
        
        # Check all rules
        for rule in self.rules:
            if self._check_rule(rule, request_data):
                self.stats['rules_matched'] += 1
                detected_threats.append(rule['name'])
                matched_rule = rule['name']
                
                # Calculate threat score based on severity
                severity_scores = {
                    'low': 0.1,
                    'medium': 0.3,
                    'high': 0.7,
                    'critical': 1.0
                }
                threat_score += severity_scores.get(rule['severity'], 0.3)
                
                # Check if rule should block
                if rule['action'] == 'block':
                    is_blocked = True
                    reason = rule.get('description', f"Rule violation: {rule['name']}")
                    self.stats['blocks'] += 1
                    break
        
        return RuleResult(
            is_blocked=is_blocked,
            reason=reason,
            threat_score=threat_score,
            detected_threats=detected_threats,
            matched_rule=matched_rule
        )
    
    def _check_rule(self, rule: Dict[str, Any], request_data: Dict[str, Any]) -> bool:
        """Check if a rule matches the request data"""
        pattern = rule['compiled_pattern']
        
        # Check URL
        if pattern.search(request_data.get('url', '')):
            return True
        
        # Check path
        if pattern.search(request_data.get('path', '')):
            return True
        
        # Check query parameters
        for key, value in request_data.get('args', {}).items():
            if pattern.search(str(value)):
                return True
        
        # Check form data
        for key, value in request_data.get('form', {}).items():
            if pattern.search(str(value)):
                return True
        
        # Check JSON data
        json_data = request_data.get('json', {})
        if json_data and self._check_json_pattern(pattern, json_data):
            return True
        
        # Check headers
        for key, value in request_data.get('headers', {}).items():
            if pattern.search(str(value)):
                return True
        
        return False
    
    def _check_json_pattern(self, pattern, data, path=""):
        """Recursively check JSON data for pattern matches"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if pattern.search(str(value)):
                    return True
                if self._check_json_pattern(pattern, value, current_path):
                    return True
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                if self._check_json_pattern(pattern, item, current_path):
                    return True
        return False
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules"""
        return [
            {
                'name': rule['name'],
                'pattern': rule['pattern'],
                'action': rule['action'],
                'severity': rule['severity'],
                'description': rule.get('description', '')
            }
            for rule in self.rules
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rule engine statistics"""
        return {
            **self.stats,
            'total_rules': len(self.rules),
            'active_rules': len([r for r in self.rules if r['action'] == 'block'])
        }
    
    def clear_rules(self):
        """Clear all custom rules (keep defaults)"""
        self.rules = []
        self._load_default_rules()
        self.logger.info("Cleared all custom rules")
    
    def update_rule(self, rule_name: str, updates: Dict[str, Any]):
        """Update an existing rule"""
        for i, rule in enumerate(self.rules):
            if rule['name'] == rule_name:
                # Update rule
                rule.update(updates)
                
                # Recompile pattern if pattern was updated
                if 'pattern' in updates:
                    rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE)
                
                self.logger.info(f"Updated rule: {rule_name}")
                return
        
        self.logger.warning(f"Rule not found: {rule_name}") 