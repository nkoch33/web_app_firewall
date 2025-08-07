# Web Application Firewall (WAF)

A comprehensive Web Application Firewall built with Python and Flask that protects web applications from common attacks using both rule-based and machine learning approaches.

## Features

- **SQL Injection Detection**: Pattern-based and ML-powered detection
- **XSS Protection**: Cross-site scripting attack prevention
- **Rate Limiting**: Configurable rate limiting per IP/user
- **Custom Rule Engine**: Flexible rule system for custom security policies
- **ML-based Threat Detection**: Machine learning models for anomaly detection
- **Real-time Monitoring**: Live dashboard for threat monitoring
- **Logging & Analytics**: Comprehensive logging and threat analytics
- **Docker Support**: Containerized deployment

## Architecture

```
Web_App_Firewall/
├── waf/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── firewall.py          # Main WAF engine
│   │   ├── rules.py             # Rule engine
│   │   ├── ml_detector.py       # ML-based detection
│   │   └── rate_limiter.py      # Rate limiting
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── sql_injection.py     # SQL injection detection
│   │   ├── xss_detector.py      # XSS detection
│   │   └── anomaly_detector.py  # Anomaly detection
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py            # API endpoints
│   │   └── middleware.py        # Request/response middleware
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── routes.py            # Dashboard routes
│   │   └── templates/           # HTML templates
│   └── utils/
│       ├── __init__.py
│       ├── logger.py            # Logging utilities
│       └── config.py            # Configuration management
├── tests/                       # Test suite
├── docker/                      # Docker configuration
├── data/                        # Training data and models
├── app.py                       # Main application
├── requirements.txt             # Dependencies
└── README.md                   # This file
```

## Quick Start

### Prerequisites

- Python 3.8+
- Redis (for rate limiting)
- Docker (optional)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Web_App_Firewall
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Start Redis (for rate limiting):
```bash
redis-server
```

6. Run the application:
```bash
python app.py
```

The WAF will be available at `http://localhost:5000`

### Docker Deployment

```bash
docker-compose up -d
```

## Usage

### Basic WAF Integration

```python
from waf.core.firewall import WAF

# Initialize WAF
waf = WAF()

# Protect a Flask app
@app.before_request
def waf_middleware():
    result = waf.analyze_request(request)
    if result.is_blocked:
        return result.response, result.status_code
```

### Custom Rules

```python
from waf.core.rules import RuleEngine

# Add custom rule
rule_engine = RuleEngine()
rule_engine.add_rule({
    'name': 'custom_block',
    'pattern': r'suspicious_pattern',
    'action': 'block',
    'severity': 'high'
})
```

## Configuration

Key configuration options in `.env`:

```env
WAF_MODE=production
WAF_LOG_LEVEL=INFO
WAF_RATE_LIMIT=100
WAF_RATE_WINDOW=3600
WAF_ML_ENABLED=true
WAF_REDIS_URL=redis://localhost:6379
```

## API Endpoints

### WAF API
- `POST /api/analyze` - Analyze request for threats
- `GET /api/stats` - Get WAF statistics
- `POST /api/rules` - Add custom rules
- `GET /api/logs` - Get security logs

### Dashboard
- `GET /dashboard` - Main dashboard
- `GET /dashboard/threats` - Threat analytics
- `GET /dashboard/rules` - Rule management

## Security Features

### SQL Injection Detection
- Pattern matching for common SQL injection patterns
- ML-based detection for sophisticated attacks
- Support for multiple SQL dialects

### XSS Protection
- Input sanitization
- Output encoding
- Content Security Policy (CSP) headers
- ML-based XSS detection

### Rate Limiting
- IP-based rate limiting
- User-based rate limiting
- Configurable limits and windows
- Redis-backed storage

### ML-based Detection
- Anomaly detection using isolation forests
- Feature extraction from HTTP requests
- Real-time threat scoring
- Model retraining capabilities

## Testing

Run the test suite:

```bash
pytest tests/
```

Run security tests:

```bash
python -m pytest tests/test_security.py -v
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Security Notice


This WAF is designed for educational and development purposes. For production use, ensure proper testing and consider additional security measures. 
