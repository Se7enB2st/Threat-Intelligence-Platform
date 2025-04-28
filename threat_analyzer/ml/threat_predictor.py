import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Optional, Any
import joblib
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class ThreatPredictor:
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the Threat Predictor
        :param model_path: Path to saved model (optional)
        """
        self.model = None
        self.scaler = StandardScaler()
        self.features = [
            'virustotal_malicious_count',
            'virustotal_suspicious_count',
            'shodan_vulnerabilities_count',
            'shodan_ports_count',
            'alienvault_pulse_count',
            'alienvault_reputation',
            'historical_threat_score',
            'days_since_first_seen'
        ]
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )

    def prepare_features(self, threat_data: Dict[str, Any]) -> np.ndarray:
        """
        Prepare features for prediction
        :param threat_data: Dictionary containing threat intelligence data
        :return: Numpy array of prepared features
        """
        features = np.zeros(len(self.features))
        
        # Extract features from threat data
        vt_data = threat_data.get('virustotal', {})
        shodan_data = threat_data.get('shodan', {})
        av_data = threat_data.get('alienvault', {})
        
        # VirusTotal features
        features[0] = vt_data.get('malicious_count', 0)
        features[1] = vt_data.get('suspicious_count', 0)
        
        # Shodan features
        features[2] = len(shodan_data.get('vulnerabilities', []))
        features[3] = len(shodan_data.get('ports', []))
        
        # AlienVault features
        features[4] = av_data.get('pulse_count', 0)
        features[5] = av_data.get('reputation', 0)
        
        # Historical features
        features[6] = threat_data.get('historical_threat_score', 0)
        first_seen = threat_data.get('first_seen')
        if first_seen:
            days_since = (datetime.utcnow() - first_seen).days
            features[7] = days_since
        
        return self.scaler.fit_transform(features.reshape(1, -1))

    def predict_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict threat level based on threat intelligence data
        :param threat_data: Dictionary containing threat intelligence data
        :return: Dictionary containing prediction results
        """
        try:
            if not self.model:
                raise ValueError("Model not initialized")
            
            features = self.prepare_features(threat_data)
            prediction = self.model.predict(features)[0]
            probability = self.model.predict_proba(features)[0]
            
            return {
                'is_malicious': bool(prediction),
                'malicious_probability': float(probability[1]),
                'confidence': float(max(probability)),
                'features_used': self.features
            }
        except Exception as e:
            logger.error(f"Error predicting threat: {str(e)}")
            return {
                'is_malicious': False,
                'malicious_probability': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }

    def train_model(self, training_data: List[Dict[str, Any]]) -> None:
        """
        Train the model on historical data
        :param training_data: List of dictionaries containing historical threat data
        """
        try:
            X = []
            y = []
            
            for data in training_data:
                features = self.prepare_features(data)
                X.append(features[0])
                y.append(data.get('is_malicious', False))
            
            X = np.array(X)
            y = np.array(y)
            
            self.model.fit(X, y)
            logger.info("Model trained successfully")
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            raise

    def save_model(self, path: str) -> None:
        """
        Save the trained model
        :param path: Path to save the model
        """
        try:
            joblib.dump({
                'model': self.model,
                'scaler': self.scaler,
                'features': self.features
            }, path)
            logger.info(f"Model saved to {path}")
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            raise

    def load_model(self, path: str) -> None:
        """
        Load a trained model
        :param path: Path to the saved model
        """
        try:
            saved_data = joblib.load(path)
            self.model = saved_data['model']
            self.scaler = saved_data['scaler']
            self.features = saved_data['features']
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

    def analyze_threat_patterns(self, threat_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze patterns in threat data
        :param threat_data: List of threat data points
        :return: Dictionary containing pattern analysis results
        """
        try:
            df = pd.DataFrame(threat_data)
            
            # Calculate statistics
            stats = {
                'total_samples': len(df),
                'malicious_percentage': (df['is_malicious'].sum() / len(df)) * 100,
                'average_threat_score': df['overall_threat_score'].mean(),
                'common_vulnerabilities': self._get_common_vulnerabilities(df),
                'threat_trends': self._analyze_threat_trends(df)
            }
            
            return stats
        except Exception as e:
            logger.error(f"Error analyzing threat patterns: {str(e)}")
            return {'error': str(e)}

    def _get_common_vulnerabilities(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Get most common vulnerabilities from the data"""
        vulnerabilities = []
        for vulns in df['shodan_data'].apply(lambda x: x.get('vulnerabilities', [])):
            vulnerabilities.extend(vulns)
        
        vuln_counts = pd.Series(vulnerabilities).value_counts()
        return [{'vulnerability': vuln, 'count': count} 
                for vuln, count in vuln_counts.head(10).items()]

    def _analyze_threat_trends(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze threat trends over time"""
        df['date'] = pd.to_datetime(df['last_updated'])
        daily_stats = df.groupby(df['date'].dt.date).agg({
            'overall_threat_score': 'mean',
            'is_malicious': 'sum'
        }).reset_index()
        
        return {
            'daily_threat_scores': daily_stats.to_dict('records'),
            'trend_direction': 'increasing' if daily_stats['overall_threat_score'].iloc[-1] > 
                              daily_stats['overall_threat_score'].iloc[0] else 'decreasing'
        } 