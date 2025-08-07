"""
WAF ML-based Threat Detector
Uses machine learning to detect sophisticated attacks
"""

import pickle
import numpy as np
import pandas as pd
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import os
import joblib

from ..utils.logger import get_logger

@dataclass
class MLResult:
    """Result of ML-based analysis"""
    is_threat: bool
    threat_score: float
    reason: str
    features: Dict[str, float]

class MLDetector:
    """Machine learning-based threat detection"""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize ML detector"""
        self.logger = get_logger(__name__)
        
        # Model configuration
        self.model_path = model_path or 'data/waf_ml_model.pkl'
        self.vectorizer_path = 'data/waf_vectorizer.pkl'
        self.scaler_path = 'data/waf_scaler.pkl'
        
        # ML components
        self.isolation_forest = None
        self.vectorizer = None
        self.scaler = None
        
        # Statistics
        self.stats = {
            'total_analyses': 0,
            'threats_detected': 0,
            'anomalies_detected': 0
        }
        
        # Initialize models
        self._load_or_create_models()
    
    def _load_or_create_models(self):
        """Load existing models or create new ones"""
        try:
            # Try to load existing models
            if os.path.exists(self.model_path):
                self.isolation_forest = joblib.load(self.model_path)
                self.logger.info("Loaded existing ML model")
            else:
                self._create_new_models()
            
            if os.path.exists(self.vectorizer_path):
                self.vectorizer = joblib.load(self.vectorizer_path)
                self.logger.info("Loaded existing vectorizer")
            else:
                self._create_vectorizer()
            
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                self.logger.info("Loaded existing scaler")
            else:
                self._create_scaler()
                
        except Exception as e:
            self.logger.warning(f"Error loading ML models: {str(e)}")
            self._create_new_models()
    
    def _create_new_models(self):
        """Create new ML models"""
        try:
            # Create isolation forest for anomaly detection
            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Train with sample data
            self._train_with_sample_data()
            
            # Save model
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.isolation_forest, self.model_path)
            
            self.logger.info("Created new ML model")
            
        except Exception as e:
            self.logger.error(f"Error creating ML model: {str(e)}")
            self.isolation_forest = None
    
    def _create_vectorizer(self):
        """Create text vectorizer"""
        try:
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 3),
                stop_words='english'
            )
            
            # Train with sample data
            sample_texts = self._get_sample_texts()
            self.vectorizer.fit(sample_texts)
            
            # Save vectorizer
            os.makedirs(os.path.dirname(self.vectorizer_path), exist_ok=True)
            joblib.dump(self.vectorizer, self.vectorizer_path)
            
            self.logger.info("Created new vectorizer")
            
        except Exception as e:
            self.logger.error(f"Error creating vectorizer: {str(e)}")
            self.vectorizer = None
    
    def _create_scaler(self):
        """Create feature scaler"""
        try:
            self.scaler = StandardScaler()
            
            # Train with sample data
            sample_features = self._get_sample_features()
            self.scaler.fit(sample_features)
            
            # Save scaler
            os.makedirs(os.path.dirname(self.scaler_path), exist_ok=True)
            joblib.dump(self.scaler, self.scaler_path)
            
            self.logger.info("Created new scaler")
            
        except Exception as e:
            self.logger.error(f"Error creating scaler: {str(e)}")
            self.scaler = None
    
    def _get_sample_texts(self) -> List[str]:
        """Get sample texts for vectorizer training"""
        return [
            "normal request",
            "GET /api/users",
            "POST /login",
            "SELECT * FROM users",
            "UNION SELECT",
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "admin' OR '1'='1",
            "'; DROP TABLE users; --",
            "normal user input",
            "legitimate form data",
            "valid json payload",
            "standard http request",
            "browser user agent",
            "mobile app request"
        ]
    
    def _get_sample_features(self) -> np.ndarray:
        """Get sample features for scaler training"""
        # Create sample feature matrix
        sample_features = []
        
        # Normal requests
        for _ in range(50):
            features = [
                np.random.normal(100, 20),  # content_length
                np.random.normal(0.1, 0.05),  # entropy
                np.random.normal(5, 2),  # param_count
                np.random.normal(10, 3),  # header_count
                np.random.normal(0.8, 0.1),  # text_ratio
                np.random.normal(0.1, 0.05),  # special_char_ratio
                np.random.normal(0.05, 0.02),  # digit_ratio
                np.random.normal(0.1, 0.05),  # uppercase_ratio
            ]
            sample_features.append(features)
        
        # Anomalous requests
        for _ in range(10):
            features = [
                np.random.normal(5000, 1000),  # large content_length
                np.random.normal(0.8, 0.1),  # high entropy
                np.random.normal(20, 5),  # many parameters
                np.random.normal(30, 10),  # many headers
                np.random.normal(0.3, 0.1),  # low text_ratio
                np.random.normal(0.5, 0.1),  # high special_char_ratio
                np.random.normal(0.3, 0.1),  # high digit_ratio
                np.random.normal(0.4, 0.1),  # high uppercase_ratio
            ]
            sample_features.append(features)
        
        return np.array(sample_features)
    
    def _train_with_sample_data(self):
        """Train models with sample data"""
        try:
            # Get sample features
            sample_features = self._get_sample_features()
            
            # Train isolation forest
            self.isolation_forest.fit(sample_features)
            
            self.logger.info("Trained ML model with sample data")
            
        except Exception as e:
            self.logger.error(f"Error training ML model: {str(e)}")
    
    def analyze(self, request_data: Dict[str, Any]) -> MLResult:
        """Analyze request using ML models"""
        self.stats['total_analyses'] += 1
        
        if not self.isolation_forest:
            return MLResult(
                is_threat=False,
                threat_score=0.0,
                reason="ML model not available",
                features={}
            )
        
        try:
            # Extract features
            features = self._extract_features(request_data)
            
            # Vectorize text features
            text_features = self._extract_text_features(request_data)
            
            # Combine features
            combined_features = np.concatenate([features, text_features])
            
            # Scale features
            if self.scaler:
                combined_features = self.scaler.transform([combined_features])[0]
            
            # Predict anomaly
            anomaly_score = self.isolation_forest.decision_function([combined_features])[0]
            
            # Convert to threat score (0-1 scale)
            threat_score = max(0, min(1, (1 - anomaly_score) / 2))
            
            # Determine if it's a threat
            is_threat = threat_score > 0.6
            
            if is_threat:
                self.stats['threats_detected'] += 1
                self.stats['anomalies_detected'] += 1
            
            # Create feature dictionary for debugging
            feature_dict = {
                'content_length': features[0],
                'entropy': features[1],
                'param_count': features[2],
                'header_count': features[3],
                'text_ratio': features[4],
                'special_char_ratio': features[5],
                'digit_ratio': features[6],
                'uppercase_ratio': features[7],
                'anomaly_score': anomaly_score,
                'threat_score': threat_score
            }
            
            return MLResult(
                is_threat=is_threat,
                threat_score=threat_score,
                reason=f"ML anomaly score: {anomaly_score:.3f}",
                features=feature_dict
            )
            
        except Exception as e:
            self.logger.error(f"ML analysis error: {str(e)}")
            return MLResult(
                is_threat=False,
                threat_score=0.0,
                reason=f"ML analysis error: {str(e)}",
                features={}
            )
    
    def _extract_features(self, request_data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from request"""
        # Content length
        content_length = float(request_data.get('content_length', 0))
        
        # Calculate entropy of request data
        all_text = str(request_data.get('url', '')) + str(request_data.get('args', '')) + str(request_data.get('form', ''))
        entropy = self._calculate_entropy(all_text)
        
        # Parameter count
        param_count = len(request_data.get('args', {})) + len(request_data.get('form', {}))
        
        # Header count
        header_count = len(request_data.get('headers', {}))
        
        # Text ratio (alphanumeric vs special chars)
        text_ratio = self._calculate_text_ratio(all_text)
        
        # Special character ratio
        special_char_ratio = self._calculate_special_char_ratio(all_text)
        
        # Digit ratio
        digit_ratio = self._calculate_digit_ratio(all_text)
        
        # Uppercase ratio
        uppercase_ratio = self._calculate_uppercase_ratio(all_text)
        
        return np.array([
            content_length,
            entropy,
            param_count,
            header_count,
            text_ratio,
            special_char_ratio,
            digit_ratio,
            uppercase_ratio
        ])
    
    def _extract_text_features(self, request_data: Dict[str, Any]) -> np.ndarray:
        """Extract text-based features using TF-IDF"""
        if not self.vectorizer:
            return np.zeros(1000)  # Default size
        
        # Combine all text data
        text_data = [
            str(request_data.get('url', '')),
            str(request_data.get('args', '')),
            str(request_data.get('form', '')),
            str(request_data.get('json', '')),
            str(request_data.get('user_agent', ''))
        ]
        
        combined_text = ' '.join(text_data)
        
        try:
            # Transform text
            text_features = self.vectorizer.transform([combined_text]).toarray()[0]
            return text_features
        except Exception:
            return np.zeros(1000)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            p = count / length
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _calculate_text_ratio(self, text: str) -> float:
        """Calculate ratio of alphanumeric characters"""
        if not text:
            return 0.0
        
        alphanumeric = sum(1 for c in text if c.isalnum())
        return alphanumeric / len(text)
    
    def _calculate_special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters"""
        if not text:
            return 0.0
        
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special_chars / len(text)
    
    def _calculate_digit_ratio(self, text: str) -> float:
        """Calculate ratio of digits"""
        if not text:
            return 0.0
        
        digits = sum(1 for c in text if c.isdigit())
        return digits / len(text)
    
    def _calculate_uppercase_ratio(self, text: str) -> float:
        """Calculate ratio of uppercase letters"""
        if not text:
            return 0.0
        
        uppercase = sum(1 for c in text if c.isupper())
        return uppercase / len(text)
    
    def retrain_model(self, training_data: List[Dict[str, Any]]):
        """Retrain the ML model with new data"""
        try:
            # Extract features from training data
            features_list = []
            for data in training_data:
                features = self._extract_features(data)
                features_list.append(features)
            
            features_array = np.array(features_list)
            
            # Retrain isolation forest
            self.isolation_forest.fit(features_array)
            
            # Save updated model
            joblib.dump(self.isolation_forest, self.model_path)
            
            self.logger.info(f"Retrained ML model with {len(training_data)} samples")
            
        except Exception as e:
            self.logger.error(f"Error retraining ML model: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ML detector statistics"""
        return {
            **self.stats,
            'model_loaded': self.isolation_forest is not None,
            'vectorizer_loaded': self.vectorizer is not None,
            'scaler_loaded': self.scaler is not None
        } 