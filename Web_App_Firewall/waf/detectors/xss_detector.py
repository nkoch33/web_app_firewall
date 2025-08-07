"""
XSS Detector
Detects cross-site scripting attacks using pattern matching
"""

import re
import html
from dataclasses import dataclass
from typing import Dict, List, Any
from urllib.parse import unquote

from ..utils.logger import get_logger

@dataclass
class XSSResult:
    """Result of XSS detection"""
    is_detected: bool
    reason: str
    confidence: float
    matched_patterns: List[str]
    payload: str
    xss_type: str

class XSSDetector:
    """Cross-site scripting detection using pattern matching"""
    
    def __init__(self):
        """Initialize XSS detector"""
        self.logger = get_logger(__name__)
        
        # XSS patterns
        self.patterns = self._load_xss_patterns()
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'detections': 0,
            'reflected_xss': 0,
            'stored_xss': 0,
            'dom_xss': 0
        }
    
    def _load_xss_patterns(self) -> List[Dict[str, Any]]:
        """Load XSS detection patterns"""
        return [
            # Basic script tags
            {
                'name': 'script_tag',
                'pattern': r'<script[^>]*>.*?</script>',
                'confidence': 0.9,
                'xss_type': 'reflected',
                'description': 'Script tag detected'
            },
            # JavaScript protocol
            {
                'name': 'javascript_protocol',
                'pattern': r'javascript:',
                'confidence': 0.8,
                'xss_type': 'reflected',
                'description': 'JavaScript protocol detected'
            },
            # Event handlers
            {
                'name': 'event_handlers',
                'pattern': r'on\w+\s*=',
                'confidence': 0.7,
                'xss_type': 'reflected',
                'description': 'Event handler detected'
            },
            # Common event handlers
            {
                'name': 'common_events',
                'pattern': r'on(load|click|mouseover|focus|blur|change|submit|error)',
                'confidence': 0.8,
                'xss_type': 'reflected',
                'description': 'Common event handler detected'
            },
            # CSS expressions
            {
                'name': 'css_expression',
                'pattern': r'expression\s*\(',
                'confidence': 0.7,
                'xss_type': 'reflected',
                'description': 'CSS expression detected'
            },
            # Data URLs
            {
                'name': 'data_url',
                'pattern': r'data:text/html|data:application/x-javascript',
                'confidence': 0.8,
                'xss_type': 'reflected',
                'description': 'Data URL with script content'
            },
            # VBScript
            {
                'name': 'vbscript',
                'pattern': r'vbscript:',
                'confidence': 0.9,
                'xss_type': 'reflected',
                'description': 'VBScript protocol detected'
            },
            # Object tags
            {
                'name': 'object_tag',
                'pattern': r'<object[^>]*>.*?</object>',
                'confidence': 0.6,
                'xss_type': 'reflected',
                'description': 'Object tag detected'
            },
            # Embed tags
            {
                'name': 'embed_tag',
                'pattern': r'<embed[^>]*>',
                'confidence': 0.6,
                'xss_type': 'reflected',
                'description': 'Embed tag detected'
            },
            # Iframe tags
            {
                'name': 'iframe_tag',
                'pattern': r'<iframe[^>]*>.*?</iframe>',
                'confidence': 0.7,
                'xss_type': 'reflected',
                'description': 'Iframe tag detected'
            },
            # Meta refresh
            {
                'name': 'meta_refresh',
                'pattern': r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*>',
                'confidence': 0.6,
                'xss_type': 'reflected',
                'description': 'Meta refresh tag detected'
            },
            # Base64 encoded
            {
                'name': 'base64_encoded',
                'pattern': r'data:text/html;base64,',
                'confidence': 0.8,
                'xss_type': 'reflected',
                'description': 'Base64 encoded script detected'
            },
            # URL encoding
            {
                'name': 'url_encoded',
                'pattern': r'%3Cscript|%3Ciframe|%3Cobject|%3Cembed',
                'confidence': 0.7,
                'xss_type': 'reflected',
                'description': 'URL-encoded XSS detected'
            },
            # Double encoding
            {
                'name': 'double_encoded',
                'pattern': r'%253Cscript|%253Ciframe|%253Cobject',
                'confidence': 0.8,
                'xss_type': 'reflected',
                'description': 'Double-encoded XSS detected'
            },
            # Hex encoding
            {
                'name': 'hex_encoded',
                'pattern': r'\\x3Cscript|\\x3Ciframe|\\x3Cobject',
                'confidence': 0.7,
                'xss_type': 'reflected',
                'description': 'Hex-encoded XSS detected'
            },
            # Unicode encoding
            {
                'name': 'unicode_encoded',
                'pattern': r'\\u003Cscript|\\u003Ciframe|\\u003Cobject',
                'confidence': 0.7,
                'xss_type': 'reflected',
                'description': 'Unicode-encoded XSS detected'
            },
            # DOM XSS patterns
            {
                'name': 'dom_xss',
                'pattern': r'document\.(write|writeln|innerHTML|outerHTML)',
                'confidence': 0.8,
                'xss_type': 'dom',
                'description': 'DOM XSS pattern detected'
            },
            # Eval function
            {
                'name': 'eval_function',
                'pattern': r'eval\s*\(',
                'confidence': 0.8,
                'xss_type': 'reflected',
                'description': 'Eval function detected'
            },
            # Function constructor
            {
                'name': 'function_constructor',
                'pattern': r'Function\s*\(',
                'confidence': 0.7,
                'xss_type': 'reflected',
                'description': 'Function constructor detected'
            },
            # SetTimeout with string
            {
                'name': 'settimeout_string',
                'pattern': r'setTimeout\s*\(\s*["\'][^"\']*["\']',
                'confidence': 0.6,
                'xss_type': 'reflected',
                'description': 'SetTimeout with string detected'
            },
            # SetInterval with string
            {
                'name': 'setinterval_string',
                'pattern': r'setInterval\s*\(\s*["\'][^"\']*["\']',
                'confidence': 0.6,
                'xss_type': 'reflected',
                'description': 'SetInterval with string detected'
            },
            # Alert function
            {
                'name': 'alert_function',
                'pattern': r'alert\s*\(',
                'confidence': 0.5,
                'xss_type': 'reflected',
                'description': 'Alert function detected'
            },
            # Confirm function
            {
                'name': 'confirm_function',
                'pattern': r'confirm\s*\(',
                'confidence': 0.5,
                'xss_type': 'reflected',
                'description': 'Confirm function detected'
            },
            # Prompt function
            {
                'name': 'prompt_function',
                'pattern': r'prompt\s*\(',
                'confidence': 0.5,
                'xss_type': 'reflected',
                'description': 'Prompt function detected'
            }
        ]
        
        # Compile patterns
        for pattern in self.patterns:
            pattern['compiled'] = re.compile(pattern['pattern'], re.IGNORECASE)
    
    def detect(self, request_data: Dict[str, Any]) -> XSSResult:
        """Detect XSS in request data"""
        self.stats['total_checks'] += 1
        
        matched_patterns = []
        max_confidence = 0.0
        detected_payload = ""
        xss_type = "unknown"
        
        # Check all data sources
        data_sources = [
            ('url', request_data.get('url', '')),
            ('args', str(request_data.get('args', ''))),
            ('form', str(request_data.get('form', ''))),
            ('json', str(request_data.get('json', ''))),
            ('headers', str(request_data.get('headers', '')))
        ]
        
        for source_name, data in data_sources:
            # URL decode the data
            decoded_data = unquote(data)
            
            # HTML decode the data
            html_decoded_data = html.unescape(decoded_data)
            
            # Check each pattern
            for pattern in self.patterns:
                # Check both encoded and decoded data
                for test_data in [decoded_data, html_decoded_data]:
                    if pattern['compiled'].search(test_data):
                        matched_patterns.append(pattern['name'])
                        
                        if pattern['confidence'] > max_confidence:
                            max_confidence = pattern['confidence']
                            detected_payload = test_data
                            xss_type = pattern['xss_type']
                        
                        self.logger.debug(f"XSS pattern '{pattern['name']}' matched in {source_name}")
        
        # Determine if XSS is detected
        is_detected = len(matched_patterns) > 0 and max_confidence > 0.5
        
        if is_detected:
            self.stats['detections'] += 1
            
            # Update specific XSS type statistics
            if xss_type == 'reflected':
                self.stats['reflected_xss'] += 1
            elif xss_type == 'stored':
                self.stats['stored_xss'] += 1
            elif xss_type == 'dom':
                self.stats['dom_xss'] += 1
            
            reason = f"XSS attack detected: {', '.join(matched_patterns)}"
        else:
            reason = ""
        
        return XSSResult(
            is_detected=is_detected,
            reason=reason,
            confidence=max_confidence,
            matched_patterns=matched_patterns,
            payload=detected_payload[:200] if detected_payload else "",  # Limit payload length
            xss_type=xss_type
        )
    
    def add_custom_pattern(self, name: str, pattern: str, confidence: float, xss_type: str, description: str):
        """Add a custom XSS pattern"""
        try:
            new_pattern = {
                'name': name,
                'pattern': pattern,
                'confidence': confidence,
                'xss_type': xss_type,
                'description': description,
                'compiled': re.compile(pattern, re.IGNORECASE)
            }
            
            self.patterns.append(new_pattern)
            self.logger.info(f"Added custom XSS pattern: {name}")
            
        except Exception as e:
            self.logger.error(f"Error adding custom pattern {name}: {str(e)}")
    
    def remove_pattern(self, pattern_name: str):
        """Remove a pattern by name"""
        self.patterns = [p for p in self.patterns if p['name'] != pattern_name]
        self.logger.info(f"Removed XSS pattern: {pattern_name}")
    
    def get_patterns(self) -> List[Dict[str, Any]]:
        """Get all XSS patterns"""
        return [
            {
                'name': pattern['name'],
                'pattern': pattern['pattern'],
                'confidence': pattern['confidence'],
                'xss_type': pattern['xss_type'],
                'description': pattern['description']
            }
            for pattern in self.patterns
        ]
    
    def test_payload(self, payload: str) -> XSSResult:
        """Test a specific payload for XSS"""
        test_data = {
            'url': payload,
            'args': {},
            'form': {},
            'json': {},
            'headers': {}
        }
        
        return self.detect(test_data)
    
    def sanitize_input(self, input_text: str) -> str:
        """Sanitize input to prevent XSS"""
        # HTML encode special characters
        sanitized = html.escape(input_text)
        
        # Remove script tags
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE)
        
        # Remove event handlers
        sanitized = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)
        
        # Remove javascript protocol
        sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def get_stats(self) -> Dict[str, Any]:
        """Get XSS detector statistics"""
        return {
            **self.stats,
            'total_patterns': len(self.patterns),
            'detection_rate': self.stats['detections'] / max(1, self.stats['total_checks']),
            'xss_types': {
                'reflected': self.stats['reflected_xss'],
                'stored': self.stats['stored_xss'],
                'dom': self.stats['dom_xss']
            }
        }
    
    def update_pattern_confidence(self, pattern_name: str, new_confidence: float):
        """Update confidence level for a pattern"""
        for pattern in self.patterns:
            if pattern['name'] == pattern_name:
                pattern['confidence'] = new_confidence
                self.logger.info(f"Updated confidence for pattern {pattern_name}: {new_confidence}")
                return
        
        self.logger.warning(f"Pattern not found: {pattern_name}")
    
    def detect_encoded_xss(self, text: str) -> bool:
        """Detect encoded XSS attempts"""
        # Check for common encoding patterns
        encoded_patterns = [
            r'%3Cscript',  # URL-encoded <script
            r'%3Ciframe',  # URL-encoded <iframe
            r'%3Cobject',  # URL-encoded <object
            r'%3Cembed',   # URL-encoded <embed
            r'\\x3Cscript',  # Hex-encoded <script
            r'\\x3Ciframe',  # Hex-encoded <iframe
            r'\\u003Cscript',  # Unicode-encoded <script
            r'\\u003Ciframe',  # Unicode-encoded <iframe
        ]
        
        for pattern in encoded_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def analyze_context(self, text: str) -> Dict[str, Any]:
        """Analyze the context of potential XSS"""
        context_analysis = {
            'has_quotes': bool(re.search(r'["\']', text)),
            'has_script_tags': bool(re.search(r'<script', text, re.IGNORECASE)),
            'has_event_handlers': bool(re.search(r'on\w+', text, re.IGNORECASE)),
            'has_javascript_protocol': bool(re.search(r'javascript:', text, re.IGNORECASE)),
            'has_encoded_content': self.detect_encoded_xss(text),
            'length': len(text),
            'special_char_ratio': len(re.findall(r'[<>"\']', text)) / max(1, len(text))
        }
        
        return context_analysis 