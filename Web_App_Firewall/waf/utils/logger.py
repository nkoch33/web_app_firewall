"""
WAF Logging Utilities
Centralized logging configuration and utilities
"""

import logging
import os
import sys
from datetime import datetime
from typing import Optional

def setup_logger(name: str = 'waf', level: Optional[str] = None) -> logging.Logger:
    """Setup and configure logger for WAF"""
    
    # Get log level from environment or use default
    log_level = level or os.getenv('WAF_LOG_LEVEL', 'INFO')
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    # Create file handler for WAF logs
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    file_handler = logging.FileHandler(f'{log_dir}/waf.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Create security log handler
    security_handler = logging.FileHandler(f'{log_dir}/security.log')
    security_handler.setLevel(logging.WARNING)
    security_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    security_handler.setFormatter(security_formatter)
    logger.addHandler(security_handler)
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the given name"""
    return logging.getLogger(f'waf.{name}')

def log_security_event(event_type: str, details: dict, level: str = 'WARNING'):
    """Log a security event"""
    logger = get_logger('security')
    
    # Create security event message
    message = f"SECURITY_EVENT: {event_type} - {details}"
    
    # Log with appropriate level
    if level.upper() == 'INFO':
        logger.info(message)
    elif level.upper() == 'WARNING':
        logger.warning(message)
    elif level.upper() == 'ERROR':
        logger.error(message)
    elif level.upper() == 'CRITICAL':
        logger.critical(message)
    else:
        logger.warning(message)

def log_threat_detection(threat_type: str, request_data: dict, confidence: float, ip: str):
    """Log a threat detection event"""
    logger = get_logger('threats')
    
    # Extract relevant information
    url = request_data.get('url', '')
    method = request_data.get('method', '')
    user_agent = request_data.get('user_agent', '')
    
    # Create threat log message
    message = (
        f"THREAT_DETECTED: {threat_type} | "
        f"IP: {ip} | "
        f"Method: {method} | "
        f"URL: {url} | "
        f"Confidence: {confidence:.2f} | "
        f"User-Agent: {user_agent[:100]}"
    )
    
    logger.warning(message)

def log_rate_limit_violation(ip: str, limit_type: str, current_count: int, limit: int):
    """Log a rate limit violation"""
    logger = get_logger('rate_limiting')
    
    message = (
        f"RATE_LIMIT_VIOLATION: {limit_type} | "
        f"IP: {ip} | "
        f"Current: {current_count} | "
        f"Limit: {limit}"
    )
    
    logger.warning(message)

def log_rule_violation(rule_name: str, request_data: dict, ip: str):
    """Log a rule violation"""
    logger = get_logger('rules')
    
    url = request_data.get('url', '')
    method = request_data.get('method', '')
    
    message = (
        f"RULE_VIOLATION: {rule_name} | "
        f"IP: {ip} | "
        f"Method: {method} | "
        f"URL: {url}"
    )
    
    logger.warning(message)

def log_anomaly_detection(anomaly_type: str, score: float, features: dict, ip: str):
    """Log an anomaly detection"""
    logger = get_logger('anomaly')
    
    # Create feature summary
    feature_summary = ', '.join([f"{k}: {v}" for k, v in features.items() if isinstance(v, (int, float))])
    
    message = (
        f"ANOMALY_DETECTED: {anomaly_type} | "
        f"IP: {ip} | "
        f"Score: {score:.2f} | "
        f"Features: {feature_summary}"
    )
    
    logger.warning(message)

def log_ml_detection(is_threat: bool, threat_score: float, features: dict, ip: str):
    """Log an ML-based detection"""
    logger = get_logger('ml')
    
    if is_threat:
        message = (
            f"ML_THREAT_DETECTED | "
            f"IP: {ip} | "
            f"Score: {threat_score:.2f} | "
            f"Features: {len(features)} extracted"
        )
        logger.warning(message)
    else:
        message = (
            f"ML_ANALYSIS | "
            f"IP: {ip} | "
            f"Score: {threat_score:.2f} | "
            f"Status: Clean"
        )
        logger.debug(message)

def log_performance_metric(metric_name: str, value: float, unit: str = ''):
    """Log a performance metric"""
    logger = get_logger('performance')
    
    message = f"PERFORMANCE: {metric_name} = {value}{unit}"
    logger.info(message)

def log_configuration_change(component: str, old_value: str, new_value: str):
    """Log a configuration change"""
    logger = get_logger('config')
    
    message = f"CONFIG_CHANGE: {component} | Old: {old_value} | New: {new_value}"
    logger.info(message)

def log_startup_info(version: str, mode: str, host: str, port: int):
    """Log startup information"""
    logger = get_logger('startup')
    
    message = (
        f"WAF_STARTUP | "
        f"Version: {version} | "
        f"Mode: {mode} | "
        f"Host: {host} | "
        f"Port: {port}"
    )
    
    logger.info(message)

def log_shutdown_info():
    """Log shutdown information"""
    logger = get_logger('shutdown')
    
    message = "WAF_SHUTDOWN: Graceful shutdown initiated"
    logger.info(message)

def create_audit_log(operation: str, user: str, details: dict):
    """Create an audit log entry"""
    logger = get_logger('audit')
    
    # Create audit message
    details_str = ', '.join([f"{k}: {v}" for k, v in details.items()])
    
    message = (
        f"AUDIT_LOG: {operation} | "
        f"User: {user} | "
        f"Details: {details_str} | "
        f"Timestamp: {datetime.now().isoformat()}"
    )
    
    logger.info(message)

def log_error_with_context(error: Exception, context: dict):
    """Log an error with additional context"""
    logger = get_logger('errors')
    
    # Create context string
    context_str = ', '.join([f"{k}: {v}" for k, v in context.items()])
    
    message = (
        f"ERROR: {str(error)} | "
        f"Context: {context_str} | "
        f"Type: {type(error).__name__}"
    )
    
    logger.error(message, exc_info=True) 