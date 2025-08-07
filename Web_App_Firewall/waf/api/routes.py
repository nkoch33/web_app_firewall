"""
WAF API Routes
REST API endpoints for WAF management and monitoring
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import time

from ..utils.logger import get_logger

# Create blueprint
api_bp = Blueprint('api', __name__)
logger = get_logger(__name__)

@api_bp.route('/analyze', methods=['POST'])
def analyze_request():
    """Analyze a request for threats"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Create a mock request object for analysis
        from flask import Request
        mock_request = Request.from_values(
            path=data.get('path', '/'),
            base_url=data.get('base_url', 'http://localhost'),
            method=data.get('method', 'GET'),
            input_stream=None,
            content_type=data.get('content_type', ''),
            headers=data.get('headers', {}),
            data=data.get('body', ''),
            environ={
                'REMOTE_ADDR': data.get('remote_addr', '127.0.0.1'),
                'HTTP_USER_AGENT': data.get('user_agent', ''),
                'HTTP_REFERER': data.get('referer', ''),
                'CONTENT_LENGTH': str(len(data.get('body', '')))
            }
        )
        
        # Analyze with WAF
        result = current_app.waf.analyze_request(mock_request)
        
        return jsonify({
            'is_blocked': result.is_blocked,
            'reason': result.reason,
            'request_id': result.request_id,
            'threat_score': result.threat_score,
            'detected_threats': result.detected_threats,
            'timestamp': result.timestamp
        })
        
    except Exception as e:
        logger.error(f"Error analyzing request: {str(e)}")
        return jsonify({'error': 'Analysis failed'}), 500

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get WAF statistics"""
    try:
        stats = current_app.waf.get_statistics()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@api_bp.route('/rules', methods=['GET', 'POST', 'DELETE'])
def manage_rules():
    """Manage WAF rules"""
    try:
        if request.method == 'GET':
            # Get all rules
            rules = current_app.waf.rule_engine.get_rules()
            return jsonify({'rules': rules})
        
        elif request.method == 'POST':
            # Add new rule
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No rule data provided'}), 400
            
            current_app.waf.rule_engine.add_rule(data)
            return jsonify({'message': 'Rule added successfully'}), 201
        
        elif request.method == 'DELETE':
            # Remove rule
            rule_name = request.args.get('name')
            if not rule_name:
                return jsonify({'error': 'Rule name required'}), 400
            
            current_app.waf.rule_engine.remove_rule(rule_name)
            return jsonify({'message': 'Rule removed successfully'})
            
    except Exception as e:
        logger.error(f"Error managing rules: {str(e)}")
        return jsonify({'error': 'Rule management failed'}), 500

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Get WAF logs"""
    try:
        log_type = request.args.get('type', 'all')
        limit = int(request.args.get('limit', 100))
        
        # This would typically read from log files
        # For now, return a mock response
        logs = {
            'security': [
                {
                    'timestamp': datetime.now().isoformat(),
                    'level': 'WARNING',
                    'message': 'SQL injection attempt detected',
                    'ip': '192.168.1.100'
                }
            ],
            'access': [
                {
                    'timestamp': datetime.now().isoformat(),
                    'ip': '192.168.1.100',
                    'method': 'GET',
                    'path': '/api/users',
                    'status': 200
                }
            ]
        }
        
        if log_type == 'security':
            return jsonify({'logs': logs['security']})
        elif log_type == 'access':
            return jsonify({'logs': logs['access']})
        else:
            return jsonify({'logs': logs})
            
    except Exception as e:
        logger.error(f"Error getting logs: {str(e)}")
        return jsonify({'error': 'Failed to get logs'}), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        health_status = current_app.waf.get_health_status()
        return jsonify(health_status)
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@api_bp.route('/config', methods=['GET', 'PUT'])
def manage_config():
    """Manage WAF configuration"""
    try:
        if request.method == 'GET':
            # Get current configuration
            config = current_app.waf.config
            return jsonify(config)
        
        elif request.method == 'PUT':
            # Update configuration
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No configuration data provided'}), 400
            
            current_app.waf.update_config(data)
            return jsonify({'message': 'Configuration updated successfully'})
            
    except Exception as e:
        logger.error(f"Error managing config: {str(e)}")
        return jsonify({'error': 'Configuration management failed'}), 500

@api_bp.route('/rate-limit/<ip>', methods=['GET', 'DELETE'])
def manage_rate_limit(ip):
    """Manage rate limiting for specific IP"""
    try:
        if request.method == 'GET':
            # Get rate limit stats for IP
            stats = current_app.waf.rate_limiter.get_client_stats(ip)
            return jsonify(stats)
        
        elif request.method == 'DELETE':
            # Reset rate limit for IP
            current_app.waf.rate_limiter.reset_client_limit(ip)
            return jsonify({'message': f'Rate limit reset for {ip}'})
            
    except Exception as e:
        logger.error(f"Error managing rate limit: {str(e)}")
        return jsonify({'error': 'Rate limit management failed'}), 500

@api_bp.route('/threats', methods=['GET'])
def get_threats():
    """Get recent threat detections"""
    try:
        # This would typically query a database
        # For now, return mock data
        threats = [
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'sql_injection',
                'ip': '192.168.1.100',
                'confidence': 0.85,
                'payload': 'admin\' OR \'1\'=\'1',
                'blocked': True
            },
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'xss',
                'ip': '192.168.1.101',
                'confidence': 0.92,
                'payload': '<script>alert(\'xss\')</script>',
                'blocked': True
            }
        ]
        
        return jsonify({'threats': threats})
        
    except Exception as e:
        logger.error(f"Error getting threats: {str(e)}")
        return jsonify({'error': 'Failed to get threats'}), 500

@api_bp.route('/anomalies', methods=['GET'])
def get_anomalies():
    """Get recent anomaly detections"""
    try:
        # This would typically query anomaly detection history
        # For now, return mock data
        anomalies = [
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'frequency',
                'ip': '192.168.1.100',
                'score': 0.78,
                'details': 'High request frequency detected'
            },
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'content',
                'ip': '192.168.1.102',
                'score': 0.65,
                'details': 'Unusually large payload detected'
            }
        ]
        
        return jsonify({'anomalies': anomalies})
        
    except Exception as e:
        logger.error(f"Error getting anomalies: {str(e)}")
        return jsonify({'error': 'Failed to get anomalies'}), 500

@api_bp.route('/test', methods=['POST'])
def test_payload():
    """Test a payload for threats"""
    try:
        data = request.get_json()
        if not data or 'payload' not in data:
            return jsonify({'error': 'Payload required'}), 400
        
        payload = data['payload']
        test_type = data.get('type', 'all')
        
        results = {}
        
        if test_type in ['all', 'sql']:
            sql_result = current_app.waf.sql_detector.test_payload(payload)
            results['sql_injection'] = {
                'detected': sql_result.is_detected,
                'confidence': sql_result.confidence,
                'reason': sql_result.reason
            }
        
        if test_type in ['all', 'xss']:
            xss_result = current_app.waf.xss_detector.test_payload(payload)
            results['xss'] = {
                'detected': xss_result.is_detected,
                'confidence': xss_result.confidence,
                'reason': xss_result.reason
            }
        
        return jsonify({
            'payload': payload,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error testing payload: {str(e)}")
        return jsonify({'error': 'Payload testing failed'}), 500

@api_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """Get performance metrics"""
    try:
        # This would typically collect real metrics
        # For now, return mock data
        metrics = {
            'requests_per_second': 45.2,
            'average_response_time': 0.15,
            'blocked_requests_percentage': 2.3,
            'memory_usage_mb': 128.5,
            'cpu_usage_percentage': 12.8,
            'active_connections': 23,
            'uptime_seconds': int(time.time())
        }
        
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Error getting metrics: {str(e)}")
        return jsonify({'error': 'Failed to get metrics'}), 500

@api_bp.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    """Manage IP whitelist"""
    try:
        if request.method == 'GET':
            # Get whitelist
            # This would typically read from a file or database
            whitelist = ['127.0.0.1', '192.168.1.1']
            return jsonify({'whitelist': whitelist})
        
        elif request.method == 'POST':
            # Add to whitelist
            data = request.get_json()
            if not data or 'ip' not in data:
                return jsonify({'error': 'IP address required'}), 400
            
            # This would typically add to whitelist
            return jsonify({'message': f'Added {data["ip"]} to whitelist'})
        
        elif request.method == 'DELETE':
            # Remove from whitelist
            ip = request.args.get('ip')
            if not ip:
                return jsonify({'error': 'IP address required'}), 400
            
            # This would typically remove from whitelist
            return jsonify({'message': f'Removed {ip} from whitelist'})
            
    except Exception as e:
        logger.error(f"Error managing whitelist: {str(e)}")
        return jsonify({'error': 'Whitelist management failed'}), 500

@api_bp.route('/blacklist', methods=['GET', 'POST', 'DELETE'])
def manage_blacklist():
    """Manage IP blacklist"""
    try:
        if request.method == 'GET':
            # Get blacklist
            # This would typically read from a file or database
            blacklist = ['192.168.1.100', '10.0.0.50']
            return jsonify({'blacklist': blacklist})
        
        elif request.method == 'POST':
            # Add to blacklist
            data = request.get_json()
            if not data or 'ip' not in data:
                return jsonify({'error': 'IP address required'}), 400
            
            # This would typically add to blacklist
            return jsonify({'message': f'Added {data["ip"]} to blacklist'})
        
        elif request.method == 'DELETE':
            # Remove from blacklist
            ip = request.args.get('ip')
            if not ip:
                return jsonify({'error': 'IP address required'}), 400
            
            # This would typically remove from blacklist
            return jsonify({'message': f'Removed {ip} from blacklist'})
            
    except Exception as e:
        logger.error(f"Error managing blacklist: {str(e)}")
        return jsonify({'error': 'Blacklist management failed'}), 500 