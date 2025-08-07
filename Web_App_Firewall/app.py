#!/usr/bin/env python3
"""
Web Application Firewall (WAF) - Main Application
A comprehensive WAF built with Python and Flask
"""

import os
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import WAF components
from waf.core.firewall import WAF
from waf.api.routes import api_bp
from waf.dashboard.routes import dashboard_bp
from waf.utils.logger import setup_logger
from waf.utils.config import Config

def create_app():
    """Create and configure the Flask application"""
    
    # Initialize Flask app
    app = Flask(__name__)
    
    # Load configuration
    config = Config()
    app.config.from_object(config)
    
    # Setup logging
    setup_logger()
    
    # Enable CORS
    CORS(app)
    
    # Initialize WAF
    waf = WAF()
    app.waf = waf
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    
    # WAF middleware - analyze all requests
    @app.before_request
    def waf_middleware():
        """WAF middleware to analyze all incoming requests"""
        try:
            # Skip WAF for static files and health checks
            if request.path.startswith('/static/') or request.path == '/health':
                return None
            
            # Analyze request with WAF
            result = waf.analyze_request(request)
            
            if result.is_blocked:
                logging.warning(f"Request blocked by WAF: {request.remote_addr} - {result.reason}")
                return jsonify({
                    'error': 'Request blocked by WAF',
                    'reason': result.reason,
                    'request_id': result.request_id
                }), 403
            
            # Add security headers
            response = app.make_response()
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
            
            return None
            
        except Exception as e:
            logging.error(f"WAF middleware error: {str(e)}")
            return None
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'waf_status': 'active',
            'version': '1.0.0'
        })
    
    # Root endpoint
    @app.route('/')
    def root():
        """Root endpoint with WAF information"""
        return jsonify({
            'message': 'Web Application Firewall (WAF)',
            'version': '1.0.0',
            'status': 'active',
            'endpoints': {
                'api': '/api',
                'dashboard': '/dashboard',
                'health': '/health'
            }
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    return app

def main():
    """Main function to run the WAF application"""
    
    # Create Flask app
    app = create_app()
    
    # Get configuration
    host = os.getenv('WAF_HOST', '0.0.0.0')
    port = int(os.getenv('WAF_PORT', 5000))
    debug = os.getenv('WAF_DEBUG', 'False').lower() == 'true'
    
    # Log startup information
    logging.info(f"Starting WAF on {host}:{port}")
    logging.info(f"Debug mode: {debug}")
    logging.info(f"WAF mode: {os.getenv('WAF_MODE', 'development')}")
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )

if __name__ == '__main__':
    main() 