"""
Security Tests for WAF
Test various security features and threat detection
"""

import pytest
from unittest.mock import Mock, patch
from flask import Request

from waf.core.firewall import WAF
from waf.detectors.sql_injection import SQLInjectionDetector
from waf.detectors.xss_detector import XSSDetector
from waf.detectors.anomaly_detector import AnomalyDetector

class TestSQLInjectionDetection:
    """Test SQL injection detection"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.sql_detector = SQLInjectionDetector()
    
    def test_basic_sql_injection(self):
        """Test basic SQL injection detection"""
        payload = "admin' OR '1'='1"
        result = self.sql_detector.test_payload(payload)
        
        assert result.is_detected == True
        assert result.confidence > 0.5
    
    def test_union_sql_injection(self):
        """Test UNION-based SQL injection"""
        payload = "UNION SELECT username,password FROM users"
        result = self.sql_detector.test_payload(payload)
        
        assert result.is_detected == True
        assert result.confidence > 0.7
    
    def test_encoded_sql_injection(self):
        """Test URL-encoded SQL injection"""
        payload = "%27%20OR%20%271%27%3D%271"
        result = self.sql_detector.test_payload(payload)
        
        assert result.is_detected == True
    
    def test_legitimate_input(self):
        """Test legitimate input should not be detected"""
        payload = "normal user input"
        result = self.sql_detector.test_payload(payload)
        
        assert result.is_detected == False

class TestXSSDetection:
    """Test XSS detection"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.xss_detector = XSSDetector()
    
    def test_basic_xss(self):
        """Test basic XSS detection"""
        payload = "<script>alert('xss')</script>"
        result = self.xss_detector.test_payload(payload)
        
        assert result.is_detected == True
        assert result.confidence > 0.8
    
    def test_javascript_protocol(self):
        """Test JavaScript protocol XSS"""
        payload = "javascript:alert('xss')"
        result = self.xss_detector.test_payload(payload)
        
        assert result.is_detected == True
        assert result.confidence > 0.7
    
    def test_event_handler_xss(self):
        """Test event handler XSS"""
        payload = "onclick=alert('xss')"
        result = self.xss_detector.test_payload(payload)
        
        assert result.is_detected == True
    
    def test_encoded_xss(self):
        """Test encoded XSS"""
        payload = "%3Cscript%3Ealert('xss')%3C/script%3E"
        result = self.xss_detector.test_payload(payload)
        
        assert result.is_detected == True
    
    def test_legitimate_html(self):
        """Test legitimate HTML should not be detected"""
        payload = "<div>Hello World</div>"
        result = self.xss_detector.test_payload(payload)
        
        assert result.is_detected == False

class TestAnomalyDetection:
    """Test anomaly detection"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.anomaly_detector = AnomalyDetector()
    
    def test_large_payload_anomaly(self):
        """Test large payload anomaly"""
        request_data = {
            'content_length': 50000,
            'url': 'http://example.com',
            'args': {},
            'form': {},
            'json': {},
            'headers': {},
            'user_agent': 'Mozilla/5.0',
            'content_type': 'application/json',
            'method': 'POST',
            'remote_addr': '192.168.1.100',
            'timestamp': 1234567890
        }
        
        result = self.anomaly_detector.detect(request_data)
        
        assert result.is_detected == True
        assert result.score > 0.5
    
    def test_rapid_requests_anomaly(self):
        """Test rapid requests anomaly"""
        # Simulate rapid requests
        for i in range(10):
            request_data = {
                'content_length': 100,
                'url': 'http://example.com',
                'args': {},
                'form': {},
                'json': {},
                'headers': {},
                'user_agent': 'Mozilla/5.0',
                'content_type': 'application/json',
                'method': 'GET',
                'remote_addr': '192.168.1.100',
                'timestamp': 1234567890 + i
            }
            
            result = self.anomaly_detector.detect(request_data)
        
        # The last request should be detected as anomalous
        assert result.is_detected == True
    
    def test_normal_request(self):
        """Test normal request should not be anomalous"""
        request_data = {
            'content_length': 100,
            'url': 'http://example.com',
            'args': {},
            'form': {},
            'json': {},
            'headers': {},
            'user_agent': 'Mozilla/5.0',
            'content_type': 'application/json',
            'method': 'GET',
            'remote_addr': '192.168.1.100',
            'timestamp': 1234567890
        }
        
        result = self.anomaly_detector.detect(request_data)
        
        assert result.is_detected == False

class TestWAFIntegration:
    """Test WAF integration"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.waf = WAF()
    
    def test_sql_injection_blocking(self):
        """Test SQL injection blocking"""
        # Create mock request
        mock_request = Mock()
        mock_request.method = 'POST'
        mock_request.url = 'http://example.com/login'
        mock_request.path = '/login'
        mock_request.headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        mock_request.args = {}
        mock_request.form = {'username': "admin' OR '1'='1"}
        mock_request.get_json.return_value = None
        mock_request.remote_addr = '192.168.1.100'
        
        result = self.waf.analyze_request(mock_request)
        
        assert result.is_blocked == True
        assert 'sql_injection' in result.detected_threats
    
    def test_xss_blocking(self):
        """Test XSS blocking"""
        # Create mock request
        mock_request = Mock()
        mock_request.method = 'POST'
        mock_request.url = 'http://example.com/comment'
        mock_request.path = '/comment'
        mock_request.headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        mock_request.args = {}
        mock_request.form = {'comment': '<script>alert("xss")</script>'}
        mock_request.get_json.return_value = None
        mock_request.remote_addr = '192.168.1.100'
        
        result = self.waf.analyze_request(mock_request)
        
        assert result.is_blocked == True
        assert 'xss_attack' in result.detected_threats
    
    def test_legitimate_request(self):
        """Test legitimate request should not be blocked"""
        # Create mock request
        mock_request = Mock()
        mock_request.method = 'GET'
        mock_request.url = 'http://example.com/api/users'
        mock_request.path = '/api/users'
        mock_request.headers = {'Content-Type': 'application/json'}
        mock_request.args = {}
        mock_request.form = {}
        mock_request.get_json.return_value = None
        mock_request.remote_addr = '192.168.1.100'
        
        result = self.waf.analyze_request(mock_request)
        
        assert result.is_blocked == False
        assert len(result.detected_threats) == 0

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def setup_method(self):
        """Setup test fixtures"""
        from waf.core.rate_limiter import RateLimiter
        self.rate_limiter = RateLimiter()
    
    @patch('waf.core.rate_limiter.redis')
    def test_rate_limit_exceeded(self, mock_redis):
        """Test rate limit exceeded"""
        # Mock Redis response
        mock_redis_client = Mock()
        mock_redis_client.pipeline.return_value.execute.return_value = [0, 11]  # 11 requests
        mock_redis_client.zrange.return_value = [('1234567890', 1234567890)]
        self.rate_limiter.redis_client = mock_redis_client
        
        # Create mock request
        mock_request = Mock()
        mock_request.remote_addr = '192.168.1.100'
        mock_request.headers = {}
        
        result = self.rate_limiter.check_rate_limit(mock_request)
        
        assert result.is_blocked == True
        assert 'rate limit exceeded' in result.reason.lower()

class TestRuleEngine:
    """Test rule engine functionality"""
    
    def setup_method(self):
        """Setup test fixtures"""
        from waf.core.rules import RuleEngine
        self.rule_engine = RuleEngine()
    
    def test_custom_rule(self):
        """Test custom rule addition"""
        custom_rule = {
            'name': 'test_rule',
            'pattern': r'test_pattern',
            'action': 'block',
            'severity': 'high',
            'description': 'Test rule'
        }
        
        self.rule_engine.add_rule(custom_rule)
        
        rules = self.rule_engine.get_rules()
        rule_names = [rule['name'] for rule in rules]
        
        assert 'test_rule' in rule_names
    
    def test_rule_violation(self):
        """Test rule violation detection"""
        request_data = {
            'url': 'http://example.com/test_pattern',
            'args': {},
            'form': {},
            'json': {},
            'headers': {}
        }
        
        result = self.rule_engine.analyze_request(request_data)
        
        # Should detect the test pattern
        assert result.is_blocked == True or len(result.detected_threats) > 0

if __name__ == '__main__':
    pytest.main([__file__]) 