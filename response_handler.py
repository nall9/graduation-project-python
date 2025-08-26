import os
import shutil
import logging
from typing import Dict, Any
import json
from datetime import datetime

class ResponseHandler:
    def __init__(self):
        self.logger = self._setup_logger()
        self.quarantine_dir = "quarantine"
        self.reports_dir = "reports"
        
        # Create necessary directories
        for directory in [self.quarantine_dir, self.reports_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
                
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for response handler"""
        logger = logging.getLogger('ResponseHandler')
        logger.setLevel(logging.INFO)
        
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        file_handler = logging.FileHandler('logs/response_handler.log')
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        return logger
        
    def handle(self, static_results: Dict[str, Any], 
               dynamic_results: Dict[str, Any],
               ml_results: Dict[str, Any],
               threat_results: Dict[str, Any]) -> Dict[str, Any]:
        """Handle the detection results and take appropriate action"""
        response = {
            'actions_taken': [],
            'quarantine_path': None,
            'report_path': None,
            'error': None
        }
        
        try:
            # Determine threat level
            threat_level = self._assess_threat_level(
                static_results, dynamic_results, ml_results, threat_results)
                
            # Take appropriate action based on threat level
            if threat_level == 'high':
                response['actions_taken'].append('quarantine')
                response['quarantine_path'] = self._quarantine_file(
                    static_results.get('file_info', {}).get('path'))
                    
            elif threat_level == 'medium':
                response['actions_taken'].append('monitor')
                
            # Generate report
            response['report_path'] = self._generate_report(
                static_results, dynamic_results, ml_results, threat_results)
                
            # Log the response
            self.logger.info(f"Response actions taken: {response['actions_taken']}")
            
        except Exception as e:
            self.logger.error(f"Error handling response: {str(e)}")
            response['error'] = str(e)
            
        return response
        
    def _assess_threat_level(self, static_results: Dict[str, Any],
                            dynamic_results: Dict[str, Any],
                            ml_results: Dict[str, Any],
                            threat_results: Dict[str, Any]) -> str:
        """Assess the overall threat level based on all analysis results"""
        threat_score = 0
        
        # Static analysis score
        if static_results.get('yara_matches'):
            threat_score += len(static_results['yara_matches']) * 2
            
        if static_results.get('suspicious_strings'):
            threat_score += len(static_results['suspicious_strings'])
            
        # Dynamic analysis score
        if dynamic_results.get('process_behavior', {}).get('error'):
            threat_score += 2
            
        # ML classification score
        if ml_results.get('prediction') == 'malware':
            threat_score += 3
            
        if ml_results.get('probability', 0) > 0.8:
            threat_score += 2
            
        # Threat intelligence score
        if threat_results.get('is_malware'):
            threat_score += 3
            
        if threat_results.get('threat_level') == 'high':
            threat_score += 3
            
        # Determine threat level
        if threat_score >= 8:
            return 'high'
        elif threat_score >= 4:
            return 'medium'
        else:
            return 'low'
            
    def _quarantine_file(self, file_path: str) -> str:
        """Move the file to quarantine"""
        try:
            if not file_path or not os.path.exists(file_path):
                raise ValueError("Invalid file path")
                
            # Generate quarantine path
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = os.path.join(
                self.quarantine_dir, f"{timestamp}_{filename}")
                
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            self.logger.info(f"File quarantined: {quarantine_path}")
            return quarantine_path
            
        except Exception as e:
            self.logger.error(f"Error quarantining file: {str(e)}")
            raise
            
    def _generate_report(self, static_results: Dict[str, Any],
                        dynamic_results: Dict[str, Any],
                        ml_results: Dict[str, Any],
                        threat_results: Dict[str, Any]) -> str:
        """Generate a detailed report of the analysis"""
        try:
            # Create report data
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'static_analysis': static_results,
                'dynamic_analysis': dynamic_results,
                'ml_classification': ml_results,
                'threat_intelligence': threat_results,
                'threat_level': self._assess_threat_level(
                    static_results, dynamic_results, ml_results, threat_results)
            }
            
            # Generate report filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(
                self.reports_dir, f"analysis_report_{timestamp}.json")
                
            # Save report
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=4)
                
            self.logger.info(f"Report generated: {report_path}")
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
            
    def restore_file(self, quarantine_path: str) -> str:
        """Restore a file from quarantine"""
        try:
            if not os.path.exists(quarantine_path):
                raise ValueError("Quarantined file not found")
                
            # Generate restore path
            filename = os.path.basename(quarantine_path).split('_', 1)[1]
            restore_path = os.path.join(os.path.dirname(quarantine_path), filename)
            
            # Move file from quarantine
            shutil.move(quarantine_path, restore_path)
            
            self.logger.info(f"File restored: {restore_path}")
            return restore_path
            
        except Exception as e:
            self.logger.error(f"Error restoring file: {str(e)}")
            raise 