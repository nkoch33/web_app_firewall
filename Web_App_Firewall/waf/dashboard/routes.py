"""
WAF Dashboard Routes
Web dashboard routes for WAF monitoring and management
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from datetime import datetime, timedelta
import time

from ..utils.logger import get_logger

# Create blueprint
dashboard_bp = Blueprint('dashboard', __name__)
logger = get_logger(__name__)

@dashboard_bp.route('/')
def dashboard():
    """Main dashboard page"""
    try:
        # Get WAF statistics
        stats = current_app.waf.get_statistics()
        
        # Get configuration summary
        config = current_app.waf.config
        
        return render_template('dashboard.html', 
                             stats=stats, 
                             config=config,
                             title='WAF Dashboard')
        
    except Exception as e:
        logger.error(f"Error rendering dashboard: {str(e)}")
        return render_template('error.html', 
                             error=str(e), 
                             title='Dashboard Error')

@dashboard_bp.route('/threats')
def threats():
    """Threat monitoring page"""
    try:
        # Get recent threats (mock data for now)
        threats = [
            {
                'timestamp': datetime.now() - timedelta(minutes=5),
                'type': 'sql_injection',
                'ip': '192.168.1.100',
                'confidence': 0.85,
                'payload': 'admin\' OR \'1\'=\'1',
                'blocked': True,
                'severity': 'high'
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=10),
                'type': 'xss',
                'ip': '192.168.1.101',
                'confidence': 0.92,
                'payload': '<script>alert(\'xss\')</script>',
                'blocked': True,
                'severity': 'high'
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=15),
                'type': 'path_traversal',
                'ip': '192.168.1.102',
                'confidence': 0.78,
                'payload': '../../../etc/passwd',
                'blocked': True,
                'severity': 'medium'
            }
        ]
        
        return render_template('threats.html', 
                             threats=threats, 
                             title='Threat Monitoring')
        
    except Exception as e:
        logger.error(f"Error rendering threats page: {str(e)}")
        return render_template('error.html', 
                             error=str(e), 
                             title='Threats Error')

@dashboard_bp.route('/rules')
def rules():
    """Rule management page"""
    try:
        # Get current rules
        rules = current_app.waf.rule_engine.get_rules()
        
        return render_template('rules.html', 
                             rules=rules, 
                             title='Rule Management')
        
    except Exception as e:
        logger.error(f"Error rendering rules page: {str(e)}")
        return render_template('error.html', 
                             error=str(e), 
                             title='Rules Error')

@dashboard_bp.route('/logs')
def logs():
    """Log monitoring page"""
    try:
        log_type = request.args.get('type', 'all')
        
        # Mock log data
        logs = {
            'security': [
                {
                    'timestamp': datetime.now() - timedelta(minutes=1),
                    'level': 'WARNING',
                    'message': 'SQL injection attempt detected',
                    'ip': '192.168.1.100',
                    'details': 'Pattern: UNION SELECT'
                },
                {
                    'timestamp': datetime.now() - timedelta(minutes=2),
                    'level': 'WARNING',
                    'message': 'XSS attack detected',
                    'ip': '192.168.1.101',
                    'details': 'Pattern: <script>'
                }
            ],
            'access': [
                {
                    'timestamp': datetime.now() - timedelta(seconds=30),
                    'ip': '192.168.1.100',
                    'method': 'GET',
                    'path': '/api/users',
                    'status': 200,
                    'response_time': 0.15
                },
                {
                    'timestamp': datetime.now() - timedelta(seconds=60),
                    'ip': '192.168.1.101',
                    'method': 'POST',
                    'path': '/api/login',
                    'status': 403,
                    'response_time': 0.05
                }
            ]
        }
        
        return render_template('logs.html', 
                             logs=logs, 
                             log_type=log_type,
                             title='Log Monitoring')
        
    except Exception as e:
        logger.error(f"Error rendering logs page: {str(e)}")
        return render_template('error.html', 
                             error=str(e), 
                             title='Logs Error')

@dashboard_bp.route('/analytics')
def analytics():
    """Analytics and metrics page"""
    try:
        # Mock analytics data
        analytics_data = {
            'requests_per_hour': [45, 52, 38, 67, 89, 76, 54, 43, 65, 78, 91, 84],
            'blocked_requests': [2, 1, 3, 5, 8, 4, 2, 1, 3, 6, 9, 5],
            'threat_types': {
                'sql_injection': 35,
                'xss': 28,
                'path_traversal': 15,
                'command_injection': 12,
                'file_inclusion': 10
            },
            'top_ips': [
                {'ip': '192.168.1.100', 'requests': 156, 'blocked': 12},
                {'ip': '192.168.1.101', 'requests': 89, 'blocked': 8},
                {'ip': '192.168.1.102', 'requests': 67, 'blocked': 5}
            ],
            'response_times': {
                'avg': 0.15,
                'min': 0.05,
                'max': 0.45,
                'p95': 0.25
            }
        }
        
        return render_template('analytics.html', 
                             analytics=analytics_data,
                             title='Analytics')
        
    except Exception as e:
        logger.error(f"Error rendering analytics page: {str(e)}")
        return render_template('error.html', 
                             error=str(e), 
                             title='Analytics Error')

@dashboard_bp.route('/config')
def config():
    """Configuration management page"""
    try:
        # Get current configuration
        config = current_app.waf.config
        
        # Get configuration validation
        validation = current_app.waf.config.validate_config()
        
        return render_template('config.html', 
                             config=config,
                             validation=validation,
                             title='Configuration')
        
    except Exception as e:
        logger.error(f"Error rendering config page: {str(e)}")
        return render_template('error.html', 
                             error=str(e), 
                             title='Configuration Error')

@dashboard_bp.route('/api/stats')
def api_stats():
    """API endpoint for dashboard statistics"""
    try:
        stats = current_app.waf.get_statistics()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/threats')
def api_threats():
    """API endpoint for recent threats"""
    try:
        # Mock threats data
        threats = [
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'sql_injection',
                'ip': '192.168.1.100',
                'confidence': 0.85,
                'payload': 'admin\' OR \'1\'=\'1',
                'blocked': True
            }
        ]
        
        return jsonify({'threats': threats})
        
    except Exception as e:
        logger.error(f"Error getting threats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/metrics')
def api_metrics():
    """API endpoint for real-time metrics"""
    try:
        # Mock metrics data
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
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/rules', methods=['GET', 'POST', 'DELETE'])
def api_rules():
    """API endpoint for rule management"""
    try:
        if request.method == 'GET':
            rules = current_app.waf.rule_engine.get_rules()
            return jsonify({'rules': rules})
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No rule data provided'}), 400
            
            current_app.waf.rule_engine.add_rule(data)
            return jsonify({'message': 'Rule added successfully'}), 201
        
        elif request.method == 'DELETE':
            rule_name = request.args.get('name')
            if not rule_name:
                return jsonify({'error': 'Rule name required'}), 400
            
            current_app.waf.rule_engine.remove_rule(rule_name)
            return jsonify({'message': 'Rule removed successfully'})
            
    except Exception as e:
        logger.error(f"Error managing rules: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/config', methods=['GET', 'PUT'])
def api_config():
    """API endpoint for configuration management"""
    try:
        if request.method == 'GET':
            config = current_app.waf.config.get_all()
            return jsonify(config)
        
        elif request.method == 'PUT':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No configuration data provided'}), 400
            
            current_app.waf.update_config(data)
            return jsonify({'message': 'Configuration updated successfully'})
            
    except Exception as e:
        logger.error(f"Error managing config: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/test-payload', methods=['POST'])
def api_test_payload():
    """API endpoint for testing payloads"""
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
        return jsonify({'error': str(e)}), 500 