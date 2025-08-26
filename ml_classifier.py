import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from typing import Dict, Any, List, Optional
import logging
import magic
import shutil
from datetime import datetime

class MLClassifier:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.logger = self._setup_logger()
        self.model_path = "models/malware_classifier.joblib"
        self.scaler_path = "models/scaler.joblib"
        
        # Create models directory if it doesn't exist
        if not os.path.exists("models"):
            os.makedirs("models")
            
        # Load or train the model
        self._initialize_model()
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for ML classifier"""
        logger = logging.getLogger('MLClassifier')
        logger.setLevel(logging.INFO)
        
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        file_handler = logging.FileHandler('logs/ml_classifier.log')
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        return logger
        
    def _initialize_model(self):
        """Initialize or load the ML model"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.logger.info("Loaded existing model and scaler")
            else:
                self._train_model()
        except Exception as e:
            self.logger.error(f"Error initializing model: {str(e)}")
            self._train_model()
            
    def _train_model(self):
        """Train a new model with sample data"""
        try:
            # Create sample data for demonstration
            # In a real implementation, you would use actual malware samples
            X = np.random.rand(100, 10)  # 100 samples, 10 features
            y = np.random.randint(0, 2, 100)  # Binary classification
            
            # Scale the features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_scaled, y)
            
            # Save the model and scaler
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            
            self.logger.info("Trained and saved new model")
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            raise
            
    def _extract_features(self, results: Dict[str, Any]) -> List[float]:
        """Extract features from analysis results"""
        try:
            features = []
            
            # Extract static analysis features
            static_analysis = results.get('static_analysis', {})
            if isinstance(static_analysis, dict):
                # File information
                file_info = static_analysis.get('file_info', {})
                if isinstance(file_info, dict):
                    features.append(float(file_info.get('size', 0)))
                    features.append(float(file_info.get('entropy', 0)))
                
                # YARA matches
                yara_matches = static_analysis.get('yara_matches', [])
                if isinstance(yara_matches, list):
                    features.append(float(len(yara_matches)))
                
                # Suspicious strings
                suspicious_strings = static_analysis.get('suspicious_strings', [])
                if isinstance(suspicious_strings, list):
                    features.append(float(len(suspicious_strings)))
            
            # Extract dynamic analysis features
            dynamic_analysis = results.get('dynamic_analysis', {})
            if isinstance(dynamic_analysis, dict):
                # Process behavior
                process_behavior = dynamic_analysis.get('process_behavior', {})
                if isinstance(process_behavior, dict):
                    features.append(float(len(process_behavior.get('cpu_usage', []))))
                    features.append(float(len(process_behavior.get('memory_usage', []))))
                
                # Network activity
                network_activity = dynamic_analysis.get('network_activity', [])
                if isinstance(network_activity, list):
                    features.append(float(len(network_activity)))
                
                # File operations
                file_operations = dynamic_analysis.get('file_operations', [])
                if isinstance(file_operations, list):
                    features.append(float(len(file_operations)))
                
                # Registry operations
                registry_operations = dynamic_analysis.get('registry_operations', [])
                if isinstance(registry_operations, list):
                    features.append(float(len(registry_operations)))
            
            # Ensure we have at least one feature
            if not features:
                self.logger.error("No features could be extracted from analysis results")
                return []
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            return []
            
    def classify(self, file_path: str) -> Dict[str, Any]:
        """Classify the given file as malware or benign"""
        results = {
            'prediction': None,
            'probability': None,
            'features': None,
            'error': None
        }
        
        try:
            # Extract features
            features = self._extract_features(file_path)
            results['features'] = features.tolist()
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0]
            
            results['prediction'] = 'malware' if prediction == 1 else 'benign'
            results['probability'] = float(probability[1])  # Probability of being malware
            
        except Exception as e:
            self.logger.error(f"Error during classification: {str(e)}")
            results['error'] = str(e)
            
        return results
        
    def update_model(self, new_data: List[Dict[str, Any]]):
        """Update the model with new training data"""
        try:
            # Extract features and labels from new data
            X_new = np.array([d['features'] for d in new_data])
            y_new = np.array([1 if d['label'] == 'malware' else 0 for d in new_data])
            
            # Scale new features
            X_new_scaled = self.scaler.transform(X_new)
            
            # Update the model
            self.model.fit(X_new_scaled, y_new)
            
            # Save the updated model
            joblib.dump(self.model, self.model_path)
            
            self.logger.info("Model updated successfully")
            
        except Exception as e:
            self.logger.error(f"Error updating model: {str(e)}")
            raise

    def analyze(self, file_path: str, results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze a file and return classification results"""
        try:
            # Initialize results if not provided
            if results is None:
                results = {
                    'static_analysis': self._perform_static_analysis(file_path),
                    'dynamic_analysis': self._perform_dynamic_analysis(file_path)
                }
            
            # Ensure we have valid analysis results
            if not isinstance(results, dict):
                raise ValueError("Invalid analysis results format")
            
            # Extract features from analysis results
            features = self._extract_features(results)
            if not features:
                self.logger.error("Failed to extract features from analysis results")
                return self._create_error_response("Failed to extract features")
            
            # Scale features
            try:
                features_scaled = self.scaler.transform([features])
            except Exception as e:
                self.logger.error(f"Error scaling features: {str(e)}")
                return self._create_error_response(f"Error scaling features: {str(e)}")
            
            # Make prediction
            try:
                prediction = self.model.predict(features_scaled)[0]
                probabilities = self.model.predict_proba(features_scaled)[0]
            except Exception as e:
                self.logger.error(f"Error making prediction: {str(e)}")
                return self._create_error_response(f"Error making prediction: {str(e)}")
            
            # Calculate risk score based on prediction and analysis results
            ml_risk = float(probabilities[1])  # Probability of being malicious
            static_risk = float(results.get('static_analysis', {}).get('risk_score', 0.0))
            dynamic_risk = float(results.get('dynamic_analysis', {}).get('risk_score', 0.0))
            
            # Weighted risk score calculation
            risk_score = float((ml_risk * 0.4) + (static_risk * 0.3) + (dynamic_risk * 0.3))
            
            # Determine classification based on risk score
            if risk_score >= 0.8:
                classification = "MALICIOUS"
                explanation = "High risk score indicates malicious behavior"
            elif risk_score >= 0.6:
                classification = "SUSPICIOUS"
                explanation = "Moderate risk score indicates suspicious behavior"
            elif risk_score >= 0.4:
                classification = "POTENTIALLY DANGEROUS"
                explanation = "Low risk score but some suspicious indicators present"
            else:
                classification = "CLEAN"
                explanation = "Low risk score indicates clean file"
            
            # Create detailed report
            report = self._create_detailed_report(results, risk_score, classification, explanation)
            
            # Return final results
            return {
                'risk_score': float(risk_score),
                'classification': str(classification),
                'explanation': str(explanation),
                'ml_confidence': float(probabilities[1]),
                'static_analysis': results.get('static_analysis', {}),
                'dynamic_analysis': results.get('dynamic_analysis', {}),
                'detailed_report': report
            }
            
        except Exception as e:
            self.logger.error(f"Error during analysis: {str(e)}")
            return self._create_error_response(f"Analysis failed: {str(e)}")
            
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create a standardized error response"""
        try:
            return {
                'risk_score': float(0.0),
                'classification': str("ERROR"),
                'explanation': str(error_message),
                'ml_confidence': float(0.0),
                'static_analysis': {},
                'dynamic_analysis': {},
                'detailed_report': None
            }
        except Exception as e:
            self.logger.error(f"Error creating error response: {str(e)}")
            return {
                'risk_score': float(0.0),
                'classification': str("ERROR"),
                'explanation': str("Failed to create error response"),
                'ml_confidence': float(0.0),
                'static_analysis': {},
                'dynamic_analysis': {},
                'detailed_report': None
            }

    def _perform_static_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform static analysis on the file"""
        try:
            # Initialize results with proper types
            results = {
                'file_info': {
                    'size': float(0),
                    'entropy': float(0),
                    'type': str('Unknown')
                },
                'yara_matches': [],
                'suspicious_strings': [],
                'risk_score': float(0)
            }
            
            # Get file information
            try:
                file_size = os.path.getsize(file_path)
                results['file_info']['size'] = float(file_size)
            except Exception as e:
                self.logger.error(f"Error getting file size: {str(e)}")
            
            # Calculate entropy
            try:
                entropy = self._calculate_entropy(file_path)
                results['file_info']['entropy'] = float(entropy)
            except Exception as e:
                self.logger.error(f"Error calculating entropy: {str(e)}")
            
            # Get file type
            try:
                file_type = magic.from_file(file_path)
                results['file_info']['type'] = str(file_type)
            except Exception as e:
                self.logger.error(f"Error getting file type: {str(e)}")
            
            # Find suspicious strings
            try:
                suspicious_strings = self._find_suspicious_strings(file_path)
                results['suspicious_strings'] = [str(s) for s in suspicious_strings]
            except Exception as e:
                self.logger.error(f"Error finding suspicious strings: {str(e)}")
            
            # Calculate risk score
            try:
                risk_score = self._calculate_static_risk_score(results)
                results['risk_score'] = float(risk_score)
            except Exception as e:
                self.logger.error(f"Error calculating risk score: {str(e)}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error during static analysis: {str(e)}")
            return {
                'file_info': {
                    'size': float(0),
                    'entropy': float(0),
                    'type': str('Unknown')
                },
                'yara_matches': [],
                'suspicious_strings': [],
                'risk_score': float(0)
            }
            
    def _perform_dynamic_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform dynamic analysis on the file"""
        try:
            # Initialize results with proper types
            results = {
                'process_behavior': {
                    'pid': None,
                    'cpu_usage': [],
                    'memory_usage': [],
                    'duration': float(0),
                    'exit_code': float(0)
                },
                'network_activity': [],
                'file_operations': [],
                'registry_operations': [],
                'risk_score': float(0)
            }
            
            # Create sandbox directory if it doesn't exist
            if not os.path.exists(self.sandbox_dir):
                os.makedirs(self.sandbox_dir)
            
            # Copy file to sandbox
            sandbox_path = os.path.join(self.sandbox_dir, os.path.basename(file_path))
            try:
                shutil.copy2(file_path, sandbox_path)
            except Exception as e:
                self.logger.error(f"Error copying file to sandbox: {str(e)}")
                return results
            
            # Monitor process
            try:
                process_info = self._monitor_process(sandbox_path)
                if isinstance(process_info, dict):
                    results['process_behavior'].update(process_info)
            except Exception as e:
                self.logger.error(f"Error monitoring process: {str(e)}")
            
            # Get network activity
            try:
                network_activity = self._get_network_connections(process_info.get('pid'))
                if isinstance(network_activity, list):
                    results['network_activity'] = network_activity
            except Exception as e:
                self.logger.error(f"Error getting network activity: {str(e)}")
            
            # Get file operations
            try:
                file_operations = self._get_file_operations(process_info.get('pid'))
                if isinstance(file_operations, list):
                    results['file_operations'] = file_operations
            except Exception as e:
                self.logger.error(f"Error getting file operations: {str(e)}")
            
            # Get registry operations
            try:
                registry_operations = self._get_registry_operations(process_info.get('pid'))
                if isinstance(registry_operations, list):
                    results['registry_operations'] = registry_operations
            except Exception as e:
                self.logger.error(f"Error getting registry operations: {str(e)}")
            
            # Calculate risk score
            try:
                risk_score = self._calculate_dynamic_risk_score(results)
                results['risk_score'] = float(risk_score)
            except Exception as e:
                self.logger.error(f"Error calculating risk score: {str(e)}")
            
            # Clean up
            try:
                self._cleanup(sandbox_path)
            except Exception as e:
                self.logger.error(f"Error during cleanup: {str(e)}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}")
            return {
                'process_behavior': {
                    'pid': None,
                    'cpu_usage': [],
                    'memory_usage': [],
                    'duration': float(0),
                    'exit_code': float(0)
                },
                'network_activity': [],
                'file_operations': [],
                'registry_operations': [],
                'risk_score': float(0)
            }
            
    def _create_detailed_report(self, results: Dict[str, Any], risk_score: float, 
                              classification: str, explanation: str) -> Dict[str, Any]:
        """Create a detailed analysis report"""
        try:
            # Initialize report with proper types
            report = {
                'analysis_time': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                'risk_score': float(risk_score),
                'classification': str(classification),
                'explanation': str(explanation),
                'static_analysis': {},
                'dynamic_analysis': {}
            }
            
            # Add static analysis details
            static_analysis = results.get('static_analysis', {})
            if isinstance(static_analysis, dict):
                report['static_analysis'] = {
                    'file_info': static_analysis.get('file_info', {}),
                    'yara_matches': static_analysis.get('yara_matches', []),
                    'suspicious_strings': static_analysis.get('suspicious_strings', []),
                    'risk_score': float(static_analysis.get('risk_score', 0))
                }
            
            # Add dynamic analysis details
            dynamic_analysis = results.get('dynamic_analysis', {})
            if isinstance(dynamic_analysis, dict):
                report['dynamic_analysis'] = {
                    'process_behavior': dynamic_analysis.get('process_behavior', {}),
                    'network_activity': dynamic_analysis.get('network_activity', []),
                    'file_operations': dynamic_analysis.get('file_operations', []),
                    'registry_operations': dynamic_analysis.get('registry_operations', []),
                    'risk_score': float(dynamic_analysis.get('risk_score', 0))
                }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error creating detailed report: {str(e)}")
            return {
                'analysis_time': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                'risk_score': float(0),
                'classification': str("ERROR"),
                'explanation': str(f"Failed to create detailed report: {str(e)}"),
                'static_analysis': {},
                'dynamic_analysis': {}
            } 