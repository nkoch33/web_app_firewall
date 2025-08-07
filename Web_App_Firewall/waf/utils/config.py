"""
WAF Configuration Management
Centralized configuration handling for the WAF system
"""

import os
from typing import Dict, Any, Optional
from dotenv import load_dotenv

class Config:
    """Configuration management for WAF"""
    
    def __init__(self):
        """Initialize configuration"""
        # Load environment variables
        load_dotenv()
        
        # Default configuration
        self.defaults = {
            # WAF General Settings
            'WAF_MODE': 'development',
            'WAF_HOST': '0.0.0.0',
            'WAF_PORT': 5000,
            'WAF_DEBUG': False,
            'WAF_LOG_LEVEL': 'INFO',
            
            # Rate Limiting
            'WAF_RATE_LIMIT': 100,
            'WAF_RATE_WINDOW': 3600,
            'WAF_BURST_LIMIT': 10,
            'WAF_BURST_WINDOW': 60,
            'WAF_REDIS_URL': 'redis://localhost:6379',
            
            # ML Settings
            'WAF_ML_ENABLED': True,
            'WAF_ML_THRESHOLD': 0.7,
            'WAF_ML_MODEL_PATH': 'data/waf_ml_model.pkl',
            
            # Security Settings
            'WAF_BLOCK_SQL_INJECTION': True,
            'WAF_BLOCK_XSS': True,
            'WAF_BLOCK_PATH_TRAVERSAL': True,
            'WAF_BLOCK_COMMAND_INJECTION': True,
            'WAF_BLOCK_FILE_INCLUSION': True,
            
            # Anomaly Detection
            'WAF_ANOMALY_ENABLED': True,
            'WAF_ANOMALY_THRESHOLD': 0.6,
            'WAF_ANOMALY_WINDOW': 1000,
            
            # Logging
            'WAF_LOG_FILE': 'logs/waf.log',
            'WAF_SECURITY_LOG': 'logs/security.log',
            'WAF_AUDIT_LOG': 'logs/audit.log',
            
            # Performance
            'WAF_MAX_WORKERS': 4,
            'WAF_TIMEOUT': 30,
            'WAF_MAX_REQUEST_SIZE': 10485760,  # 10MB
            
            # Dashboard
            'WAF_DASHBOARD_ENABLED': True,
            'WAF_DASHBOARD_PORT': 5001,
            
            # API
            'WAF_API_ENABLED': True,
            'WAF_API_KEY': '',
            'WAF_API_RATE_LIMIT': 1000,
            
            # Monitoring
            'WAF_METRICS_ENABLED': True,
            'WAF_HEALTH_CHECK_INTERVAL': 30,
            
            # Advanced Settings
            'WAF_CUSTOM_RULES_FILE': 'config/custom_rules.json',
            'WAF_WHITELIST_FILE': 'config/whitelist.json',
            'WAF_BLACKLIST_FILE': 'config/blacklist.json',
            'WAF_SSL_ENABLED': False,
            'WAF_SSL_CERT': '',
            'WAF_SSL_KEY': '',
        }
        
        # Load configuration
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables and defaults"""
        config = {}
        
        # Load from environment variables with defaults
        for key, default_value in self.defaults.items():
            env_value = os.getenv(key)
            
            if env_value is not None:
                # Convert string values to appropriate types
                if isinstance(default_value, bool):
                    config[key] = env_value.lower() in ('true', '1', 'yes', 'on')
                elif isinstance(default_value, int):
                    try:
                        config[key] = int(env_value)
                    except ValueError:
                        config[key] = default_value
                elif isinstance(default_value, float):
                    try:
                        config[key] = float(env_value)
                    except ValueError:
                        config[key] = default_value
                else:
                    config[key] = env_value
            else:
                config[key] = default_value
        
        return config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values"""
        return self.config.copy()
    
    def update(self, new_config: Dict[str, Any]):
        """Update configuration with new values"""
        self.config.update(new_config)
    
    def get_waf_settings(self) -> Dict[str, Any]:
        """Get WAF-specific settings"""
        return {
            'mode': self.get('WAF_MODE'),
            'host': self.get('WAF_HOST'),
            'port': self.get('WAF_PORT'),
            'debug': self.get('WAF_DEBUG'),
            'log_level': self.get('WAF_LOG_LEVEL')
        }
    
    def get_rate_limit_settings(self) -> Dict[str, Any]:
        """Get rate limiting settings"""
        return {
            'rate_limit': self.get('WAF_RATE_LIMIT'),
            'rate_window': self.get('WAF_RATE_WINDOW'),
            'burst_limit': self.get('WAF_BURST_LIMIT'),
            'burst_window': self.get('WAF_BURST_WINDOW'),
            'redis_url': self.get('WAF_REDIS_URL')
        }
    
    def get_ml_settings(self) -> Dict[str, Any]:
        """Get ML settings"""
        return {
            'enabled': self.get('WAF_ML_ENABLED'),
            'threshold': self.get('WAF_ML_THRESHOLD'),
            'model_path': self.get('WAF_ML_MODEL_PATH')
        }
    
    def get_security_settings(self) -> Dict[str, Any]:
        """Get security settings"""
        return {
            'block_sql_injection': self.get('WAF_BLOCK_SQL_INJECTION'),
            'block_xss': self.get('WAF_BLOCK_XSS'),
            'block_path_traversal': self.get('WAF_BLOCK_PATH_TRAVERSAL'),
            'block_command_injection': self.get('WAF_BLOCK_COMMAND_INJECTION'),
            'block_file_inclusion': self.get('WAF_BLOCK_FILE_INCLUSION')
        }
    
    def get_anomaly_settings(self) -> Dict[str, Any]:
        """Get anomaly detection settings"""
        return {
            'enabled': self.get('WAF_ANOMALY_ENABLED'),
            'threshold': self.get('WAF_ANOMALY_THRESHOLD'),
            'window': self.get('WAF_ANOMALY_WINDOW')
        }
    
    def get_logging_settings(self) -> Dict[str, Any]:
        """Get logging settings"""
        return {
            'log_level': self.get('WAF_LOG_LEVEL'),
            'log_file': self.get('WAF_LOG_FILE'),
            'security_log': self.get('WAF_SECURITY_LOG'),
            'audit_log': self.get('WAF_AUDIT_LOG')
        }
    
    def get_performance_settings(self) -> Dict[str, Any]:
        """Get performance settings"""
        return {
            'max_workers': self.get('WAF_MAX_WORKERS'),
            'timeout': self.get('WAF_TIMEOUT'),
            'max_request_size': self.get('WAF_MAX_REQUEST_SIZE')
        }
    
    def get_dashboard_settings(self) -> Dict[str, Any]:
        """Get dashboard settings"""
        return {
            'enabled': self.get('WAF_DASHBOARD_ENABLED'),
            'port': self.get('WAF_DASHBOARD_PORT')
        }
    
    def get_api_settings(self) -> Dict[str, Any]:
        """Get API settings"""
        return {
            'enabled': self.get('WAF_API_ENABLED'),
            'api_key': self.get('WAF_API_KEY'),
            'rate_limit': self.get('WAF_API_RATE_LIMIT')
        }
    
    def get_monitoring_settings(self) -> Dict[str, Any]:
        """Get monitoring settings"""
        return {
            'metrics_enabled': self.get('WAF_METRICS_ENABLED'),
            'health_check_interval': self.get('WAF_HEALTH_CHECK_INTERVAL')
        }
    
    def get_ssl_settings(self) -> Dict[str, Any]:
        """Get SSL settings"""
        return {
            'enabled': self.get('WAF_SSL_ENABLED'),
            'cert': self.get('WAF_SSL_CERT'),
            'key': self.get('WAF_SSL_KEY')
        }
    
    def is_production(self) -> bool:
        """Check if running in production mode"""
        return self.get('WAF_MODE') == 'production'
    
    def is_development(self) -> bool:
        """Check if running in development mode"""
        return self.get('WAF_MODE') == 'development'
    
    def is_debug_enabled(self) -> bool:
        """Check if debug mode is enabled"""
        return self.get('WAF_DEBUG', False)
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate configuration and return any issues"""
        issues = []
        warnings = []
        
        # Check required settings
        if not self.get('WAF_HOST'):
            issues.append("WAF_HOST is not set")
        
        if not self.get('WAF_PORT'):
            issues.append("WAF_PORT is not set")
        
        # Check port range
        port = self.get('WAF_PORT')
        if port and (port < 1 or port > 65535):
            issues.append(f"WAF_PORT {port} is not in valid range (1-65535)")
        
        # Check Redis connection
        redis_url = self.get('WAF_REDIS_URL')
        if redis_url and not redis_url.startswith(('redis://', 'rediss://')):
            warnings.append("WAF_REDIS_URL format may be invalid")
        
        # Check file paths
        log_file = self.get('WAF_LOG_FILE')
        if log_file and not os.path.dirname(log_file):
            warnings.append(f"Log directory for {log_file} may not exist")
        
        # Check SSL settings
        if self.get('WAF_SSL_ENABLED'):
            cert = self.get('WAF_SSL_CERT')
            key = self.get('WAF_SSL_KEY')
            if not cert or not key:
                issues.append("SSL enabled but certificate or key not provided")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }
    
    def export_config(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Export configuration (optionally excluding sensitive data)"""
        config = self.config.copy()
        
        if not include_sensitive:
            # Remove sensitive configuration
            sensitive_keys = ['WAF_API_KEY', 'WAF_SSL_CERT', 'WAF_SSL_KEY']
            for key in sensitive_keys:
                if key in config:
                    config[key] = '***HIDDEN***'
        
        return config
    
    def reload_config(self):
        """Reload configuration from environment"""
        self.config = self._load_config()
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration"""
        return {
            'mode': self.get('WAF_MODE'),
            'host': self.get('WAF_HOST'),
            'port': self.get('WAF_PORT'),
            'debug': self.get('WAF_DEBUG'),
            'log_level': self.get('WAF_LOG_LEVEL'),
            'rate_limiting': {
                'enabled': bool(self.get('WAF_REDIS_URL')),
                'limit': self.get('WAF_RATE_LIMIT'),
                'window': self.get('WAF_RATE_WINDOW')
            },
            'ml_detection': {
                'enabled': self.get('WAF_ML_ENABLED'),
                'threshold': self.get('WAF_ML_THRESHOLD')
            },
            'security_features': {
                'sql_injection': self.get('WAF_BLOCK_SQL_INJECTION'),
                'xss': self.get('WAF_BLOCK_XSS'),
                'path_traversal': self.get('WAF_BLOCK_PATH_TRAVERSAL'),
                'command_injection': self.get('WAF_BLOCK_COMMAND_INJECTION'),
                'file_inclusion': self.get('WAF_BLOCK_FILE_INCLUSION')
            },
            'anomaly_detection': {
                'enabled': self.get('WAF_ANOMALY_ENABLED'),
                'threshold': self.get('WAF_ANOMALY_THRESHOLD')
            },
            'dashboard': {
                'enabled': self.get('WAF_DASHBOARD_ENABLED'),
                'port': self.get('WAF_DASHBOARD_PORT')
            },
            'api': {
                'enabled': self.get('WAF_API_ENABLED'),
                'has_key': bool(self.get('WAF_API_KEY'))
            },
            'ssl': {
                'enabled': self.get('WAF_SSL_ENABLED'),
                'has_cert': bool(self.get('WAF_SSL_CERT')),
                'has_key': bool(self.get('WAF_SSL_KEY'))
            }
        } 