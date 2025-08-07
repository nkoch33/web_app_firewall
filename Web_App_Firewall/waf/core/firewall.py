"""
Main WAF Firewall Engine
Coordinates all security components and provides the main interface
"""

import uuid
import time
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from flask import Request

from .rules import RuleEngine
from .rate_limiter import RateLimiter
from .ml_detector import MLDetector
from ..detectors.sql_injection import SQLInjectionDetector
from ..detectors.xss_detector import XSSDetector
from ..detectors.anomaly_detector import AnomalyDetector
from ..utils.logger import get_logger

@dataclass
class WAFResult:
    """Result of WAF analysis"""
    is_blocked: bool
    reason: str
    request_id: str
    timestamp: float
    threat_score: float
    detected_threats: List[str]
    response: Optional[Dict] = None
    status_code: int = 403

class WAF:
    """Main Web Application Firewall engine"""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize WAF with all security components"""
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Initialize security components
        self.rule_engine = RuleEngine()
        self.rate_limiter = RateLimiter()
        self.ml_detector = MLDetector()
        
        # Initialize detectors
        self.sql_detector = SQLInjectionDetector()
        self.xss_detector = XSSDetector()
        self.anomaly_detector = AnomalyDetector()
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'threats_detected': 0,
            'sql_injection_attempts': 0,
            'xss_attempts': 0,
            'rate_limit_violations': 0
        }
        
        self.logger.info("WAF initialized successfully")
    
    def analyze_request(self, request: Request) -> WAFResult:
        """Analyze incoming request for threats"""
        request_id = str(uuid.uuid4())
        start_time = time.time()
        
        # Extract request data
        request_data = self._extract_request_data(request)
        
        # Initialize result
        result = WAFResult(
            is_blocked=False,
            reason="",
            request_id=request_id,
            timestamp=start_time,
            threat_score=0.0,
            detected_threats=[]
        )
        
        try:
            # Update statistics
            self.stats['total_requests'] += 1
            
            # 1. Rate Limiting Check
            rate_limit_result = self.rate_limiter.check_rate_limit(request)
            if rate_limit_result.is_blocked:
                self.stats['rate_limit_violations'] += 1
                result.is_blocked = True
                result.reason = f"Rate limit exceeded: {rate_limit_result.reason}"
                result.detected_threats.append('rate_limit_violation')
                return result
            
            # 2. Rule-based Detection
            rule_result = self.rule_engine.analyze_request(request_data)
            if rule_result.is_blocked:
                result.is_blocked = True
                result.reason = f"Rule violation: {rule_result.reason}"
                result.detected_threats.extend(rule_result.detected_threats)
                result.threat_score += rule_result.threat_score
            
            # 3. SQL Injection Detection
            sql_result = self.sql_detector.detect(request_data)
            if sql_result.is_detected:
                self.stats['sql_injection_attempts'] += 1
                result.is_blocked = True
                result.reason = f"SQL injection detected: {sql_result.reason}"
                result.detected_threats.append('sql_injection')
                result.threat_score += 0.8
            
            # 4. XSS Detection
            xss_result = self.xss_detector.detect(request_data)
            if xss_result.is_detected:
                self.stats['xss_attempts'] += 1
                result.is_blocked = True
                result.reason = f"XSS attack detected: {xss_result.reason}"
                result.detected_threats.append('xss_attack')
                result.threat_score += 0.7
            
            # 5. Anomaly Detection
            anomaly_result = self.anomaly_detector.detect(request_data)
            if anomaly_result.is_detected:
                result.threat_score += anomaly_result.score
                result.detected_threats.append('anomaly')
                
                # Block if anomaly score is high
                if anomaly_result.score > 0.8:
                    result.is_blocked = True
                    result.reason = f"Anomaly detected: {anomaly_result.reason}"
            
            # 6. ML-based Detection
            ml_result = self.ml_detector.analyze(request_data)
            if ml_result.is_threat:
                result.threat_score += ml_result.threat_score
                result.detected_threats.append('ml_detection')
                
                if ml_result.threat_score > 0.7:
                    result.is_blocked = True
                    result.reason = f"ML threat detection: {ml_result.reason}"
            
            # Update statistics
            if result.is_blocked:
                self.stats['blocked_requests'] += 1
            
            if result.detected_threats:
                self.stats['threats_detected'] += 1
            
            # Log the analysis
            self._log_analysis(request, result)
            
        except Exception as e:
            self.logger.error(f"Error analyzing request: {str(e)}")
            result.is_blocked = True
            result.reason = "WAF analysis error"
        
        return result
    
    def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant data from Flask request"""
        return {
            'method': request.method,
            'url': request.url,
            'path': request.path,
            'headers': dict(request.headers),
            'args': dict(request.args),
            'form': dict(request.form),
            'json': request.get_json(silent=True),
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'content_type': request.headers.get('Content-Type', ''),
            'content_length': request.headers.get('Content-Length', 0),
            'referer': request.headers.get('Referer', ''),
            'timestamp': time.time()
        }
    
    def _log_analysis(self, request: Request, result: WAFResult):
        """Log the analysis result"""
        if result.is_blocked:
            self.logger.warning(
                f"Request blocked - IP: {request.remote_addr}, "
                f"Path: {request.path}, Reason: {result.reason}, "
                f"Threats: {result.detected_threats}"
            )
        elif result.detected_threats:
            self.logger.info(
                f"Threats detected - IP: {request.remote_addr}, "
                f"Path: {request.path}, Threats: {result.detected_threats}, "
                f"Score: {result.threat_score}"
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WAF statistics"""
        return {
            **self.stats,
            'uptime': time.time(),
            'components': {
                'rule_engine': self.rule_engine.get_stats(),
                'rate_limiter': self.rate_limiter.get_stats(),
                'ml_detector': self.ml_detector.get_stats()
            }
        }
    
    def add_custom_rule(self, rule: Dict[str, Any]):
        """Add a custom rule to the rule engine"""
        self.rule_engine.add_rule(rule)
        self.logger.info(f"Added custom rule: {rule.get('name', 'unnamed')}")
    
    def update_config(self, config: Dict[str, Any]):
        """Update WAF configuration"""
        self.config.update(config)
        self.logger.info("WAF configuration updated")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get WAF health status"""
        return {
            'status': 'healthy',
            'components': {
                'rule_engine': 'active',
                'rate_limiter': 'active',
                'ml_detector': 'active',
                'sql_detector': 'active',
                'xss_detector': 'active',
                'anomaly_detector': 'active'
            },
            'version': '1.0.0'
        } 