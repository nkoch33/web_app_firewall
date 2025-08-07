#!/usr/bin/env python3
"""
WAF Demo Script
Demonstrate WAF functionality with various attack scenarios
"""

import requests
import json
import time
from flask import Request
from unittest.mock import Mock

from waf.core.firewall import WAF

def create_mock_request(method='GET', url='http://example.com', path='/', 
                       headers=None, args=None, form=None, json_data=None, 
                       remote_addr='192.168.1.100'):
    """Create a mock Flask request for testing"""
    mock_request = Mock()
    mock_request.method = method
    mock_request.url = url
    mock_request.path = path
    mock_request.headers = headers or {}
    mock_request.args = args or {}
    mock_request.form = form or {}
    mock_request.get_json.return_value = json_data
    mock_request.remote_addr = remote_addr
    return mock_request

def test_sql_injection_attacks():
    """Test various SQL injection attacks"""
    print("\n=== Testing SQL Injection Attacks ===")
    
    waf = WAF()
    
    # Test cases
    sql_attacks = [
        {
            'name': 'Basic SQL Injection',
            'payload': "admin' OR '1'='1",
            'form': {'username': "admin' OR '1'='1", 'password': 'password'}
        },
        {
            'name': 'UNION-based SQL Injection',
            'payload': "UNION SELECT username,password FROM users",
            'form': {'search': "UNION SELECT username,password FROM users"}
        },
        {
            'name': 'Time-based SQL Injection',
            'payload': "'; WAITFOR DELAY '00:00:05'--",
            'form': {'id': "'; WAITFOR DELAY '00:00:05'--"}
        },
        {
            'name': 'Boolean-based SQL Injection',
            'payload': "admin' AND 1=1--",
            'form': {'username': "admin' AND 1=1--"}
        },
        {
            'name': 'Stacked Queries',
            'payload': "; DROP TABLE users--",
            'form': {'query': "; DROP TABLE users--"}
        }
    ]
    
    for attack in sql_attacks:
        print(f"\nTesting: {attack['name']}")
        print(f"Payload: {attack['payload']}")
        
        mock_request = create_mock_request(
            method='POST',
            path='/login',
            form=attack['form'],
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        result = waf.analyze_request(mock_request)
        
        print(f"Blocked: {result.is_blocked}")
        print(f"Reason: {result.reason}")
        print(f"Threat Score: {result.threat_score:.2f}")
        print(f"Detected Threats: {result.detected_threats}")

def test_xss_attacks():
    """Test various XSS attacks"""
    print("\n=== Testing XSS Attacks ===")
    
    waf = WAF()
    
    # Test cases
    xss_attacks = [
        {
            'name': 'Basic XSS',
            'payload': "<script>alert('xss')</script>",
            'form': {'comment': "<script>alert('xss')</script>"}
        },
        {
            'name': 'JavaScript Protocol',
            'payload': "javascript:alert('xss')",
            'form': {'url': "javascript:alert('xss')"}
        },
        {
            'name': 'Event Handler XSS',
            'payload': "onclick=alert('xss')",
            'form': {'input': "onclick=alert('xss')"}
        },
        {
            'name': 'Encoded XSS',
            'payload': "%3Cscript%3Ealert('xss')%3C/script%3E",
            'form': {'data': "%3Cscript%3Ealert('xss')%3C/script%3E"}
        },
        {
            'name': 'DOM XSS',
            'payload': "document.write('<script>alert(1)</script>')",
            'form': {'script': "document.write('<script>alert(1)</script>')"}
        }
    ]
    
    for attack in xss_attacks:
        print(f"\nTesting: {attack['name']}")
        print(f"Payload: {attack['payload']}")
        
        mock_request = create_mock_request(
            method='POST',
            path='/comment',
            form=attack['form'],
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        result = waf.analyze_request(mock_request)
        
        print(f"Blocked: {result.is_blocked}")
        print(f"Reason: {result.reason}")
        print(f"Threat Score: {result.threat_score:.2f}")
        print(f"Detected Threats: {result.detected_threats}")

def test_path_traversal_attacks():
    """Test path traversal attacks"""
    print("\n=== Testing Path Traversal Attacks ===")
    
    waf = WAF()
    
    # Test cases
    path_attacks = [
        {
            'name': 'Basic Path Traversal',
            'payload': "../../../etc/passwd",
            'args': {'file': "../../../etc/passwd"}
        },
        {
            'name': 'URL Encoded Path Traversal',
            'payload': "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            'args': {'file': "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"}
        },
        {
            'name': 'Double Encoded Path Traversal',
            'payload': "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            'args': {'file': "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"}
        }
    ]
    
    for attack in path_attacks:
        print(f"\nTesting: {attack['name']}")
        print(f"Payload: {attack['payload']}")
        
        mock_request = create_mock_request(
            method='GET',
            path='/download',
            args=attack['args']
        )
        
        result = waf.analyze_request(mock_request)
        
        print(f"Blocked: {result.is_blocked}")
        print(f"Reason: {result.reason}")
        print(f"Threat Score: {result.threat_score:.2f}")
        print(f"Detected Threats: {result.detected_threats}")

def test_command_injection_attacks():
    """Test command injection attacks"""
    print("\n=== Testing Command Injection Attacks ===")
    
    waf = WAF()
    
    # Test cases
    command_attacks = [
        {
            'name': 'Basic Command Injection',
            'payload': "; ls -la",
            'form': {'command': "; ls -la"}
        },
        {
            'name': 'Pipe Command Injection',
            'payload': "| cat /etc/passwd",
            'form': {'input': "| cat /etc/passwd"}
        },
        {
            'name': 'Backtick Command Injection',
            'payload': "`whoami`",
            'form': {'query': "`whoami`"}
        },
        {
            'name': 'URL Encoded Command Injection',
            'payload': "%3b%20ls%20-la",
            'form': {'data': "%3b%20ls%20-la"}
        }
    ]
    
    for attack in command_attacks:
        print(f"\nTesting: {attack['name']}")
        print(f"Payload: {attack['payload']}")
        
        mock_request = create_mock_request(
            method='POST',
            path='/execute',
            form=attack['form'],
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        result = waf.analyze_request(mock_request)
        
        print(f"Blocked: {result.is_blocked}")
        print(f"Reason: {result.reason}")
        print(f"Threat Score: {result.threat_score:.2f}")
        print(f"Detected Threats: {result.detected_threats}")

def test_legitimate_requests():
    """Test legitimate requests should not be blocked"""
    print("\n=== Testing Legitimate Requests ===")
    
    waf = WAF()
    
    # Test cases
    legitimate_requests = [
        {
            'name': 'Normal Login',
            'method': 'POST',
            'path': '/login',
            'form': {'username': 'admin', 'password': 'password123'},
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'}
        },
        {
            'name': 'API Request',
            'method': 'GET',
            'path': '/api/users',
            'headers': {'Content-Type': 'application/json'},
            'args': {'page': '1', 'limit': '10'}
        },
        {
            'name': 'File Upload',
            'method': 'POST',
            'path': '/upload',
            'form': {'file': 'document.pdf'},
            'headers': {'Content-Type': 'multipart/form-data'}
        },
        {
            'name': 'Search Query',
            'method': 'GET',
            'path': '/search',
            'args': {'q': 'python programming'}
        }
    ]
    
    for request in legitimate_requests:
        print(f"\nTesting: {request['name']}")
        
        mock_request = create_mock_request(
            method=request['method'],
            path=request['path'],
            args=request.get('args', {}),
            form=request.get('form', {}),
            headers=request.get('headers', {})
        )
        
        result = waf.analyze_request(mock_request)
        
        print(f"Blocked: {result.is_blocked}")
        print(f"Threat Score: {result.threat_score:.2f}")
        print(f"Detected Threats: {result.detected_threats}")

def test_rate_limiting():
    """Test rate limiting functionality"""
    print("\n=== Testing Rate Limiting ===")
    
    waf = WAF()
    
    # Simulate rapid requests
    print("Simulating rapid requests...")
    
    for i in range(15):
        mock_request = create_mock_request(
            method='GET',
            path='/api/test',
            remote_addr='192.168.1.100'
        )
        
        result = waf.analyze_request(mock_request)
        
        if result.is_blocked and 'rate_limit' in result.detected_threats:
            print(f"Request {i+1}: BLOCKED (Rate limit exceeded)")
            break
        else:
            print(f"Request {i+1}: ALLOWED")

def test_ml_detection():
    """Test ML-based threat detection"""
    print("\n=== Testing ML-based Detection ===")
    
    waf = WAF()
    
    # Test cases with unusual patterns
    ml_test_cases = [
        {
            'name': 'Large Payload',
            'method': 'POST',
            'path': '/api/data',
            'form': {'data': 'A' * 10000},  # Large payload
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'}
        },
        {
            'name': 'Unusual Headers',
            'method': 'GET',
            'path': '/api/test',
            'headers': {
                'User-Agent': 'sqlmap/1.0',
                'X-Forwarded-For': '192.168.1.100',
                'X-Real-IP': '192.168.1.100'
            }
        },
        {
            'name': 'High Entropy Content',
            'method': 'POST',
            'path': '/api/upload',
            'form': {'data': 'xK9#mP2$vL8@nQ4&jR7*wS5!tU3^yV6%zW1'},
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'}
        }
    ]
    
    for test_case in ml_test_cases:
        print(f"\nTesting: {test_case['name']}")
        
        mock_request = create_mock_request(
            method=test_case['method'],
            path=test_case['path'],
            form=test_case.get('form', {}),
            headers=test_case.get('headers', {})
        )
        
        result = waf.analyze_request(mock_request)
        
        print(f"Blocked: {result.is_blocked}")
        print(f"Threat Score: {result.threat_score:.2f}")
        print(f"Detected Threats: {result.detected_threats}")

def main():
    """Run all WAF tests"""
    print("WAF Demo - Testing Web Application Firewall")
    print("=" * 50)
    
    # Test all attack types
    test_sql_injection_attacks()
    test_xss_attacks()
    test_path_traversal_attacks()
    test_command_injection_attacks()
    test_legitimate_requests()
    test_rate_limiting()
    test_ml_detection()
    
    print("\n" + "=" * 50)
    print("Demo completed!")
    print("\nTo run the WAF server:")
    print("1. Copy env.example to .env")
    print("2. Install dependencies: pip install -r requirements.txt")
    print("3. Start Redis: redis-server")
    print("4. Run WAF: python app.py")
    print("5. Access dashboard: http://localhost:5000/dashboard")

if __name__ == '__main__':
    main() 