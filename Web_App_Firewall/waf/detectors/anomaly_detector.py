"""
Anomaly Detector
Detects anomalous request patterns and behaviors
"""

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Any
from collections import defaultdict, deque

from ..utils.logger import get_logger

@dataclass
class AnomalyResult:
    """Result of anomaly detection"""
    is_detected: bool
    reason: str
    score: float
    anomaly_type: str
    features: Dict[str, Any]

class AnomalyDetector:
    """Anomaly detection using statistical analysis and behavioral patterns"""
    
    def __init__(self, window_size: int = 1000):
        """Initialize anomaly detector"""
        self.logger = get_logger(__name__)
        
        # Configuration
        self.window_size = window_size
        self.request_history = deque(maxlen=window_size)
        self.ip_history = defaultdict(lambda: deque(maxlen=100))
        
        # Thresholds
        self.thresholds = {
            'content_length': {'mean': 1000, 'std': 500, 'max': 10000},
            'request_frequency': {'max_per_minute': 60, 'max_per_hour': 1000},
            'parameter_count': {'mean': 5, 'std': 3, 'max': 20},
            'header_count': {'mean': 10, 'std': 5, 'max': 30},
            'url_length': {'mean': 100, 'std': 50, 'max': 500},
            'entropy': {'min': 0.1, 'max': 0.8}
        }
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'anomalies_detected': 0,
            'frequency_anomalies': 0,
            'content_anomalies': 0,
            'behavioral_anomalies': 0
        }
        
        # Behavioral patterns
        self.suspicious_patterns = [
            # Rapid requests
            {'name': 'rapid_requests', 'pattern': r'rapid_fire', 'weight': 0.8},
            # Unusual user agents
            {'name': 'suspicious_ua', 'pattern': r'(sqlmap|nikto|nmap|wget|curl|python)', 'weight': 0.7},
            # Missing user agent
            {'name': 'missing_ua', 'pattern': r'^$', 'weight': 0.6},
            # Unusual referrers
            {'name': 'suspicious_referrer', 'pattern': r'(null|javascript:|data:)', 'weight': 0.6},
            # Large payloads
            {'name': 'large_payload', 'pattern': r'large_content', 'weight': 0.7},
            # Unusual content types
            {'name': 'unusual_content_type', 'pattern': r'(application/x-www-form-urlencoded|multipart/form-data)', 'weight': 0.5}
        ]
    
    def detect(self, request_data: Dict[str, Any]) -> AnomalyResult:
        """Detect anomalies in request data"""
        self.stats['total_checks'] += 1
        
        # Extract features
        features = self._extract_features(request_data)
        
        # Update history
        self._update_history(request_data)
        
        # Check different types of anomalies
        anomalies = []
        total_score = 0.0
        
        # 1. Content-based anomalies
        content_anomaly = self._check_content_anomalies(features)
        if content_anomaly.is_detected:
            anomalies.append(content_anomaly)
            total_score += content_anomaly.score
            self.stats['content_anomalies'] += 1
        
        # 2. Frequency-based anomalies
        frequency_anomaly = self._check_frequency_anomalies(request_data)
        if frequency_anomaly.is_detected:
            anomalies.append(frequency_anomaly)
            total_score += frequency_anomaly.score
            self.stats['frequency_anomalies'] += 1
        
        # 3. Behavioral anomalies
        behavioral_anomaly = self._check_behavioral_anomalies(request_data)
        if behavioral_anomaly.is_detected:
            anomalies.append(behavioral_anomaly)
            total_score += behavioral_anomaly.score
            self.stats['behavioral_anomalies'] += 1
        
        # 4. Statistical anomalies
        statistical_anomaly = self._check_statistical_anomalies(features)
        if statistical_anomaly.is_detected:
            anomalies.append(statistical_anomaly)
            total_score += statistical_anomaly.score
        
        # Determine if anomaly is detected
        is_detected = len(anomalies) > 0 and total_score > 0.5
        
        if is_detected:
            self.stats['anomalies_detected'] += 1
            reason = f"Anomaly detected: {', '.join([a.anomaly_type for a in anomalies])}"
        else:
            reason = ""
        
        return AnomalyResult(
            is_detected=is_detected,
            reason=reason,
            score=total_score,
            anomaly_type='combined' if len(anomalies) > 1 else anomalies[0].anomaly_type if anomalies else 'none',
            features=features
        )
    
    def _extract_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from request data"""
        # Basic features
        content_length = int(request_data.get('content_length', 0))
        param_count = len(request_data.get('args', {})) + len(request_data.get('form', {}))
        header_count = len(request_data.get('headers', {}))
        url_length = len(request_data.get('url', ''))
        
        # Calculate entropy
        all_text = str(request_data.get('url', '')) + str(request_data.get('args', '')) + str(request_data.get('form', ''))
        entropy = self._calculate_entropy(all_text)
        
        # User agent analysis
        user_agent = request_data.get('user_agent', '')
        has_user_agent = bool(user_agent.strip())
        suspicious_ua = any(pattern['pattern'] in user_agent.lower() for pattern in self.suspicious_patterns if 'ua' in pattern['name'])
        
        # Content type analysis
        content_type = request_data.get('content_type', '')
        is_form_data = 'application/x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type
        
        # Method analysis
        method = request_data.get('method', 'GET')
        is_post = method == 'POST'
        is_get = method == 'GET'
        
        return {
            'content_length': content_length,
            'param_count': param_count,
            'header_count': header_count,
            'url_length': url_length,
            'entropy': entropy,
            'has_user_agent': has_user_agent,
            'suspicious_ua': suspicious_ua,
            'is_form_data': is_form_data,
            'is_post': is_post,
            'is_get': is_get,
            'method': method,
            'timestamp': request_data.get('timestamp', time.time())
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
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
    
    def _update_history(self, request_data: Dict[str, Any]):
        """Update request history"""
        # Add to general history
        self.request_history.append({
            'timestamp': time.time(),
            'ip': request_data.get('remote_addr', ''),
            'method': request_data.get('method', ''),
            'path': request_data.get('path', ''),
            'content_length': int(request_data.get('content_length', 0))
        })
        
        # Add to IP-specific history
        ip = request_data.get('remote_addr', '')
        if ip:
            self.ip_history[ip].append({
                'timestamp': time.time(),
                'method': request_data.get('method', ''),
                'path': request_data.get('path', ''),
                'content_length': int(request_data.get('content_length', 0))
            })
    
    def _check_content_anomalies(self, features: Dict[str, Any]) -> AnomalyResult:
        """Check for content-based anomalies"""
        score = 0.0
        reasons = []
        
        # Check content length
        content_length = features['content_length']
        if content_length > self.thresholds['content_length']['max']:
            score += 0.8
            reasons.append('unusually large content length')
        
        # Check parameter count
        param_count = features['param_count']
        if param_count > self.thresholds['parameter_count']['max']:
            score += 0.6
            reasons.append('unusually high parameter count')
        
        # Check header count
        header_count = features['header_count']
        if header_count > self.thresholds['header_count']['max']:
            score += 0.5
            reasons.append('unusually high header count')
        
        # Check URL length
        url_length = features['url_length']
        if url_length > self.thresholds['url_length']['max']:
            score += 0.7
            reasons.append('unusually long URL')
        
        # Check entropy
        entropy = features['entropy']
        if entropy < self.thresholds['entropy']['min'] or entropy > self.thresholds['entropy']['max']:
            score += 0.4
            reasons.append('unusual content entropy')
        
        return AnomalyResult(
            is_detected=score > 0.3,
            reason='; '.join(reasons) if reasons else '',
            score=score,
            anomaly_type='content',
            features=features
        )
    
    def _check_frequency_anomalies(self, request_data: Dict[str, Any]) -> AnomalyResult:
        """Check for frequency-based anomalies"""
        ip = request_data.get('remote_addr', '')
        current_time = time.time()
        
        if not ip or ip not in self.ip_history:
            return AnomalyResult(
                is_detected=False,
                reason='',
                score=0.0,
                anomaly_type='frequency',
                features={}
            )
        
        # Get recent requests for this IP
        recent_requests = [
            req for req in self.ip_history[ip]
            if current_time - req['timestamp'] <= 60  # Last minute
        ]
        
        minute_count = len(recent_requests)
        
        # Get hourly requests
        hourly_requests = [
            req for req in self.ip_history[ip]
            if current_time - req['timestamp'] <= 3600  # Last hour
        ]
        
        hour_count = len(hourly_requests)
        
        score = 0.0
        reasons = []
        
        # Check minute frequency
        if minute_count > self.thresholds['request_frequency']['max_per_minute']:
            score += 0.9
            reasons.append(f'high request frequency ({minute_count}/min)')
        
        # Check hour frequency
        if hour_count > self.thresholds['request_frequency']['max_per_hour']:
            score += 0.8
            reasons.append(f'high hourly frequency ({hour_count}/hour)')
        
        # Check for rapid-fire requests (multiple requests within seconds)
        if len(recent_requests) >= 3:
            time_diffs = [
                recent_requests[i]['timestamp'] - recent_requests[i-1]['timestamp']
                for i in range(1, len(recent_requests))
            ]
            if any(diff < 1.0 for diff in time_diffs):  # Less than 1 second apart
                score += 0.7
                reasons.append('rapid-fire requests detected')
        
        return AnomalyResult(
            is_detected=score > 0.3,
            reason='; '.join(reasons) if reasons else '',
            score=score,
            anomaly_type='frequency',
            features={'minute_count': minute_count, 'hour_count': hour_count}
        )
    
    def _check_behavioral_anomalies(self, request_data: Dict[str, Any]) -> AnomalyResult:
        """Check for behavioral anomalies"""
        score = 0.0
        reasons = []
        
        # Check user agent
        user_agent = request_data.get('user_agent', '')
        if not user_agent.strip():
            score += 0.6
            reasons.append('missing user agent')
        elif any(pattern['pattern'] in user_agent.lower() for pattern in self.suspicious_patterns if 'ua' in pattern['name']):
            score += 0.7
            reasons.append('suspicious user agent')
        
        # Check referrer
        referrer = request_data.get('referer', '')
        if referrer and any(pattern['pattern'] in referrer.lower() for pattern in self.suspicious_patterns if 'referrer' in pattern['name']):
            score += 0.5
            reasons.append('suspicious referrer')
        
        # Check content type
        content_type = request_data.get('content_type', '')
        if content_type and 'unusual_content_type' in str(self.suspicious_patterns):
            score += 0.4
            reasons.append('unusual content type')
        
        # Check for missing common headers
        headers = request_data.get('headers', {})
        common_headers = ['accept', 'accept-language', 'accept-encoding']
        missing_headers = [h for h in common_headers if h not in headers]
        if len(missing_headers) > 1:
            score += 0.3
            reasons.append('missing common headers')
        
        return AnomalyResult(
            is_detected=score > 0.3,
            reason='; '.join(reasons) if reasons else '',
            score=score,
            anomaly_type='behavioral',
            features={'user_agent': user_agent, 'referrer': referrer}
        )
    
    def _check_statistical_anomalies(self, features: Dict[str, Any]) -> AnomalyResult:
        """Check for statistical anomalies using historical data"""
        if len(self.request_history) < 10:  # Need minimum data
            return AnomalyResult(
                is_detected=False,
                reason='insufficient historical data',
                score=0.0,
                anomaly_type='statistical',
                features=features
            )
        
        # Calculate statistics from history
        content_lengths = [req['content_length'] for req in self.request_history]
        mean_content_length = sum(content_lengths) / len(content_lengths)
        
        current_content_length = features['content_length']
        
        # Calculate z-score
        if mean_content_length > 0:
            z_score = abs(current_content_length - mean_content_length) / mean_content_length
        else:
            z_score = 0
        
        score = 0.0
        reasons = []
        
        # Check if current request is statistically anomalous
        if z_score > 2.0:  # More than 2 standard deviations
            score += 0.6
            reasons.append(f'statistically anomalous content length (z-score: {z_score:.2f})')
        
        # Check for unusual patterns in recent history
        recent_requests = list(self.request_history)[-10:]  # Last 10 requests
        if len(recent_requests) >= 5:
            # Check for unusual method distribution
            methods = [req['method'] for req in recent_requests]
            get_count = methods.count('GET')
            post_count = methods.count('POST')
            
            if post_count > get_count and features['is_get']:
                score += 0.4
                reasons.append('unusual method pattern')
        
        return AnomalyResult(
            is_detected=score > 0.3,
            reason='; '.join(reasons) if reasons else '',
            score=score,
            anomaly_type='statistical',
            features={'z_score': z_score, 'mean_content_length': mean_content_length}
        )
    
    def update_thresholds(self, new_thresholds: Dict[str, Any]):
        """Update anomaly detection thresholds"""
        self.thresholds.update(new_thresholds)
        self.logger.info("Updated anomaly detection thresholds")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get anomaly detector statistics"""
        return {
            **self.stats,
            'history_size': len(self.request_history),
            'unique_ips': len(self.ip_history),
            'detection_rate': self.stats['anomalies_detected'] / max(1, self.stats['total_checks'])
        }
    
    def clear_history(self):
        """Clear request history"""
        self.request_history.clear()
        self.ip_history.clear()
        self.logger.info("Cleared anomaly detection history")
    
    def get_ip_stats(self, ip: str) -> Dict[str, Any]:
        """Get statistics for a specific IP"""
        if ip not in self.ip_history:
            return {}
        
        requests = list(self.ip_history[ip])
        if not requests:
            return {}
        
        # Calculate statistics
        content_lengths = [req['content_length'] for req in requests]
        methods = [req['method'] for req in requests]
        
        return {
            'total_requests': len(requests),
            'avg_content_length': sum(content_lengths) / len(content_lengths),
            'max_content_length': max(content_lengths),
            'method_distribution': {method: methods.count(method) for method in set(methods)},
            'last_request': max(req['timestamp'] for req in requests),
            'first_request': min(req['timestamp'] for req in requests)
        } 