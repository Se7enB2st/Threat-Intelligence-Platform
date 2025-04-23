import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import json
import random

class ThreatMLDetector:
    def __init__(self):
        self.rf_classifier = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.model_path = "models/"
        
        # Define feature columns with consistent ordering
        self.feature_columns = [
            'vt_malicious_count',
            'vt_suspicious_count',
            'shodan_vuln_count',
            'shodan_port_count',
            'av_pulse_count',
            'av_reputation',
            'port_risk_score',
            'update_frequency',
            'geographic_risk'
        ]
        
        # Create models directory if it doesn't exist
        if not os.path.exists(self.model_path):
            os.makedirs(self.model_path)
            
        # Load existing models if available
        self.load_models()

    def prepare_features(self, ip_data: Dict) -> pd.DataFrame:
        """Extract and prepare features from IP data"""
        features = {}
        
        try:
            # VirusTotal features
            vt_data = ip_data.get('virustotal', {})
            if isinstance(vt_data, dict):
                if 'data' in vt_data and 'attributes' in vt_data['data']:
                    analysis_stats = vt_data['data']['attributes'].get('last_analysis_stats', {})
                    features['vt_malicious_count'] = analysis_stats.get('malicious', 0)
                    features['vt_suspicious_count'] = analysis_stats.get('suspicious', 0)
                else:
                    features['vt_malicious_count'] = 0
                    features['vt_suspicious_count'] = 0
            else:
                features['vt_malicious_count'] = 0
                features['vt_suspicious_count'] = 0
            
            # Shodan features
            shodan_data = ip_data.get('shodan', {})
            if isinstance(shodan_data, dict):
                # Handle ports
                ports = shodan_data.get('ports', [])
                if isinstance(ports, str):
                    try:
                        ports = json.loads(ports)
                    except:
                        ports = []
                features['shodan_port_count'] = len(ports)
                
                # Handle vulnerabilities
                vulns = shodan_data.get('vulns', [])
                if isinstance(vulns, str):
                    try:
                        vulns = json.loads(vulns)
                    except:
                        vulns = []
                features['shodan_vuln_count'] = len(vulns)
            else:
                features['shodan_port_count'] = 0
                features['shodan_vuln_count'] = 0
            
            # AlienVault features
            av_data = ip_data.get('alienvault', {})
            if isinstance(av_data, dict):
                features['av_pulse_count'] = av_data.get('pulse_count', 0)
                features['av_reputation'] = av_data.get('reputation', 0)
            else:
                features['av_pulse_count'] = 0
                features['av_reputation'] = 0
            
            # Calculate port risk score
            features['port_risk_score'] = self.calculate_port_risk(ports if 'ports' in locals() else [])
            
            # Update frequency
            features['update_frequency'] = 0  # Default value
            
            # Geographic risk score
            features['geographic_risk'] = self.calculate_geographic_risk(ip_data)
            
            # Create DataFrame with specific column order
            df = pd.DataFrame([{col: features.get(col, 0) for col in self.feature_columns}])
            
            return df
        
        except Exception as e:
            print(f"Error preparing features: {str(e)}")
            # Return default features if there's an error
            return pd.DataFrame([{col: 0 for col in self.feature_columns}])

    def calculate_port_risk(self, ports: List[int]) -> float:
        """Calculate risk score based on open ports"""
        high_risk_ports = {21, 23, 3389, 445, 135, 137, 138, 139}  # Known vulnerable ports
        medium_risk_ports = {80, 443, 8080, 8443, 22}  # Common service ports
        
        risk_score = 0
        for port in ports:
            if port in high_risk_ports:
                risk_score += 10
            elif port in medium_risk_ports:
                risk_score += 5
            else:
                risk_score += 1
                
        return min(100, risk_score)

    def calculate_geographic_risk(self, ip_data: Dict) -> float:
        """Calculate risk score based on geographic location"""
        # Define high-risk countries (example)
        high_risk_countries = {'CN', 'RU', 'IR', 'KP', 'SY'}
        medium_risk_countries = {'BR', 'IN', 'NG', 'VN', 'ID'}
        
        country_code = ip_data.get('country_code', '')
        
        if country_code in high_risk_countries:
            return 100
        elif country_code in medium_risk_countries:
            return 50
        return 0

    def train_models(self, training_data: pd.DataFrame):
        """Train both classification and anomaly detection models"""
        try:
            if len(training_data) < 10:
                raise ValueError("Insufficient training data")
            
            # Ensure we have all required columns
            for col in self.feature_columns:
                if col not in training_data.columns:
                    training_data[col] = 0
            
            # Select features in the correct order
            X = training_data[self.feature_columns]
            y = training_data['is_malicious'].astype(int)  # Ensure binary values
            
            # Check class balance
            if len(y.unique()) < 2:
                print("Warning: Only one class present in training data. Adding synthetic samples...")
                # Add synthetic samples for the missing class
                if y.iloc[0] == 0:
                    # Add malicious samples
                    synthetic_malicious = self._generate_synthetic_data(10, malicious=True)
                    synthetic_df = pd.DataFrame(synthetic_malicious)
                    training_data = pd.concat([training_data, synthetic_df], ignore_index=True)
                else:
                    # Add benign samples
                    synthetic_benign = self._generate_synthetic_data(10, malicious=False)
                    synthetic_df = pd.DataFrame(synthetic_benign)
                    training_data = pd.concat([training_data, synthetic_df], ignore_index=True)
                
                # Update X and y with synthetic data
                X = training_data[self.feature_columns]
                y = training_data['is_malicious'].astype(int)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Train Random Forest Classifier
            self.rf_classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                class_weight='balanced',
                random_state=42
            )
            self.rf_classifier.fit(X_train, y_train)
            
            # Train Isolation Forest for anomaly detection
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            self.anomaly_detector.fit(X_scaled)
            
            # Save models
            self.save_models()
            
            # Return model performance metrics
            return {
                'rf_accuracy': self.rf_classifier.score(X_test, y_test),
                'feature_importance': dict(zip(
                    self.feature_columns,
                    self.rf_classifier.feature_importances_
                )),
                'class_distribution': {
                    'benign': int((y == 0).sum()),
                    'malicious': int((y == 1).sum())
                }
            }

        except Exception as e:
            print(f"Training error: {str(e)}")
            raise Exception(f"Error during model training: {str(e)}")

    def _generate_synthetic_data(self, n_samples: int, malicious: bool = False) -> List[Dict]:
        """Generate synthetic data for training"""
        synthetic_data = []
        
        for _ in range(n_samples):
            if malicious:
                # Generate malicious sample
                features = {
                    'vt_malicious_count': random.randint(5, 50),
                    'vt_suspicious_count': random.randint(3, 30),
                    'shodan_vuln_count': random.randint(2, 20),
                    'shodan_port_count': random.randint(10, 100),
                    'av_pulse_count': random.randint(5, 100),
                    'av_reputation': random.randint(-100, -20),
                    'port_risk_score': random.randint(70, 100),
                    'update_frequency': random.randint(0, 365),
                    'geographic_risk': random.randint(50, 100),
                    'is_malicious': True
                }
            else:
                # Generate benign sample
                features = {
                    'vt_malicious_count': random.randint(0, 2),
                    'vt_suspicious_count': random.randint(0, 2),
                    'shodan_vuln_count': random.randint(0, 1),
                    'shodan_port_count': random.randint(1, 5),
                    'av_pulse_count': random.randint(0, 2),
                    'av_reputation': random.randint(0, 100),
                    'port_risk_score': random.randint(0, 30),
                    'update_frequency': random.randint(0, 365),
                    'geographic_risk': random.randint(0, 20),
                    'is_malicious': False
                }
            
            synthetic_data.append(features)
        
        return synthetic_data

    def predict_threat(self, ip_data: Dict) -> Dict:
        """Predict threat level for an IP address"""
        try:
            if not self.rf_classifier or not self.anomaly_detector:
                raise ValueError("Models not trained. Please train the models first.")
            
            # Prepare features
            features_df = self.prepare_features(ip_data)
            X_scaled = self.scaler.transform(features_df)
            
            # Get predictions
            threat_proba = self.rf_classifier.predict_proba(X_scaled)[0]
            is_anomaly = self.anomaly_detector.predict(X_scaled)[0] == -1
            
            # Get the probability of being malicious (second class)
            malicious_prob = threat_proba[1] if len(threat_proba) > 1 else 0.0
            
            # Calculate feature importance for this prediction
            feature_importance = dict(zip(
                self.feature_columns,
                self.rf_classifier.feature_importances_
            ))
            
            # Get top contributing factors
            top_factors = sorted(
                feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]
            
            # Calculate confidence score
            confidence_score = max(threat_proba) * 100
            
            # Prepare the response
            analysis_result = {
                'threat_probability': float(malicious_prob),
                'is_anomaly': bool(is_anomaly),
                'threat_score': float(malicious_prob * 100),
                'confidence_score': float(confidence_score),
                'top_factors': [
                    {
                        'factor': factor,
                        'importance': float(importance)
                    }
                    for factor, importance in top_factors
                ],
                'is_high_risk': bool(malicious_prob > 0.7 or is_anomaly),
                'analysis_timestamp': datetime.now().isoformat(),
                'feature_values': features_df.to_dict('records')[0]
            }
            
            return analysis_result

        except Exception as e:
            print(f"Prediction error: {str(e)}")
            raise Exception(f"Error during threat prediction: {str(e)}")

    def save_models(self):
        """Save trained models to disk"""
        if self.rf_classifier:
            joblib.dump(
                self.rf_classifier,
                os.path.join(self.model_path, 'rf_classifier.joblib')
            )
        if self.anomaly_detector:
            joblib.dump(
                self.anomaly_detector,
                os.path.join(self.model_path, 'anomaly_detector.joblib')
            )
        if self.scaler:
            joblib.dump(
                self.scaler,
                os.path.join(self.model_path, 'scaler.joblib')
            )

    def load_models(self):
        """Load trained models from disk"""
        try:
            self.rf_classifier = joblib.load(
                os.path.join(self.model_path, 'rf_classifier.joblib')
            )
            self.anomaly_detector = joblib.load(
                os.path.join(self.model_path, 'anomaly_detector.joblib')
            )
            self.scaler = joblib.load(
                os.path.join(self.model_path, 'scaler.joblib')
            )
        except:
            print("No existing models found. Need to train new models.")

    def get_model_info(self) -> Dict:
        """Get information about the current models"""
        return {
            'models_trained': bool(self.rf_classifier and self.anomaly_detector),
            'feature_columns': self.feature_columns,
            'rf_classifier_params': self.rf_classifier.get_params() if self.rf_classifier else None,
            'last_updated': datetime.fromtimestamp(
                os.path.getmtime(os.path.join(self.model_path, 'rf_classifier.joblib'))
            ).isoformat() if self.rf_classifier else None
        } 