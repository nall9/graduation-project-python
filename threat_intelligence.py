import os
import json
import hashlib
import requests
from typing import Dict, Any, List
import logging
from datetime import datetime, timedelta

class ThreatIntelligence:
    def __init__(self):
        self.logger = self._setup_logger()
        self.cache_dir = "cache"
        self.cache_file = os.path.join(self.cache_dir, "threat_cache.json")
        self.cache_duration = timedelta(hours=1)
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
            
        # Initialize cache
        self._initialize_cache()
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for threat intelligence"""
        logger = logging.getLogger('ThreatIntelligence')
        logger.setLevel(logging.INFO)
        
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        file_handler = logging.FileHandler('logs/threat_intelligence.log')
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        return logger
        
    def _initialize_cache(self):
        """Initialize or load the threat cache"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
            else:
                self.cache = {
                    'last_update': None,
                    'threats': {}
                }
                self._save_cache()
        except Exception as e:
            self.logger.error(f"Error initializing cache: {str(e)}")
            self.cache = {
                'last_update': None,
                'threats': {}
            }
            
    def _save_cache(self):
        """Save the current cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            self.logger.error(f"Error saving cache: {str(e)}")
            
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of the file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating file hash: {str(e)}")
            return ""
            
    def _check_cache(self, file_hash: str) -> Dict[str, Any]:
        """Check if the file hash exists in cache and is still valid"""
        if file_hash in self.cache['threats']:
            threat_info = self.cache['threats'][file_hash]
            last_update = datetime.fromisoformat(self.cache['last_update'])
            
            if datetime.now() - last_update < self.cache_duration:
                return threat_info
                
        return None
        
    def _update_cache(self, file_hash: str, threat_info: Dict[str, Any]):
        """Update the cache with new threat information"""
        self.cache['threats'][file_hash] = threat_info
        self.cache['last_update'] = datetime.now().isoformat()
        self._save_cache()
        
    def _query_threat_intelligence(self, file_hash: str) -> Dict[str, Any]:
        """Query external threat intelligence sources"""
        # This is a simplified version. In a real implementation,
        # you would query actual threat intelligence APIs
        try:
            # Simulate API response
            response = {
                'is_malware': False,
                'threat_level': 'low',
                'threat_type': None,
                'first_seen': None,
                'last_seen': None,
                'detection_rate': 0.0,
                'sources': []
            }
            
            # Simulate API call delay
            import time
            time.sleep(0.5)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error querying threat intelligence: {str(e)}")
            return None
            
    def check_file(self, file_path: str) -> Dict[str, Any]:
        """Check if a file is known to be malicious"""
        results = {
            'is_malware': False,
            'threat_level': 'unknown',
            'threat_type': None,
            'detection_rate': 0.0,
            'sources': [],
            'error': None
        }
        
        try:
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            if not file_hash:
                results['error'] = "Could not calculate file hash"
                return results
                
            # Check cache first
            cached_result = self._check_cache(file_hash)
            if cached_result:
                return cached_result
                
            # Query threat intelligence
            threat_info = self._query_threat_intelligence(file_hash)
            if threat_info:
                # Update cache
                self._update_cache(file_hash, threat_info)
                return threat_info
                
        except Exception as e:
            self.logger.error(f"Error checking file: {str(e)}")
            results['error'] = str(e)
            
        return results
        
    def update_threat_database(self):
        """Update the local threat database"""
        try:
            # This is a simplified version. In a real implementation,
            # you would update from actual threat intelligence sources
            self.logger.info("Updating threat database...")
            
            # Simulate database update
            import time
            time.sleep(1)
            
            self.logger.info("Threat database updated successfully")
            
        except Exception as e:
            self.logger.error(f"Error updating threat database: {str(e)}")
            raise 