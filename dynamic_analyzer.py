import os
import subprocess
import psutil
import time
from typing import Dict, Any, List
import json
import logging

class DynamicAnalyzer:
    def __init__(self):
        self.sandbox_dir = "sandbox"
        self.logger = self._setup_logger()
        
        # Create sandbox directory if it doesn't exist
        if not os.path.exists(self.sandbox_dir):
            os.makedirs(self.sandbox_dir)
            
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for dynamic analysis"""
        logger = logging.getLogger('DynamicAnalyzer')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        file_handler = logging.FileHandler('logs/dynamic_analysis.log')
        file_handler.setLevel(logging.INFO)
        
        # Create formatters and add it to handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        # Add handlers to the logger
        logger.addHandler(file_handler)
        
        return logger
        
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform dynamic analysis on the given file"""
        results = {
            'process_behavior': {},
            'network_activity': [],
            'file_operations': [],
            'registry_operations': [],
            'system_calls': []
        }
        
        try:
            # Create a copy of the file in the sandbox
            sandbox_path = os.path.join(self.sandbox_dir, os.path.basename(file_path))
            with open(file_path, 'rb') as src, open(sandbox_path, 'wb') as dst:
                dst.write(src.read())
            
            # Monitor and analyze the process
            process_info = self._monitor_process(sandbox_path)
            results['process_behavior'] = process_info
            
            # Clean up
            self._cleanup(sandbox_path)
            
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}")
            results['error'] = str(e)
            
        return results
        
    def _monitor_process(self, file_path: str) -> Dict[str, Any]:
        """Monitor process behavior during execution"""
        process_info = {
            'pid': None,
            'cpu_usage': [],
            'memory_usage': [],
            'duration': 0,
            'exit_code': None
        }
        
        try:
            # Start the process
            process = subprocess.Popen(
                [file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            process_info['pid'] = process.pid
            start_time = time.time()
            
            # Monitor the process
            while process.poll() is None:
                try:
                    p = psutil.Process(process.pid)
                    process_info['cpu_usage'].append(p.cpu_percent())
                    process_info['memory_usage'].append(p.memory_info().rss)
                    time.sleep(0.1)
                except psutil.NoSuchProcess:
                    break
                    
            # Get process duration and exit code
            process_info['duration'] = time.time() - start_time
            process_info['exit_code'] = process.poll()
            
            # Get stdout and stderr
            stdout, stderr = process.communicate()
            process_info['stdout'] = stdout.decode('utf-8', errors='ignore')
            process_info['stderr'] = stderr.decode('utf-8', errors='ignore')
            
        except Exception as e:
            self.logger.error(f"Error monitoring process: {str(e)}")
            process_info['error'] = str(e)
            
        return process_info
        
    def _cleanup(self, file_path: str):
        """Clean up after analysis"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")
            
    def _get_network_connections(self, pid: int) -> List[Dict[str, Any]]:
        """Get network connections made by the process"""
        connections = []
        try:
            process = psutil.Process(pid)
            for conn in process.connections():
                connections.append({
                    'local_addr': conn.laddr,
                    'remote_addr': conn.raddr,
                    'status': conn.status,
                    'type': conn.type
                })
        except Exception as e:
            self.logger.error(f"Error getting network connections: {str(e)}")
        return connections
        
    def _get_file_operations(self, pid: int) -> List[Dict[str, Any]]:
        """Get file operations performed by the process"""
        # This is a simplified version. In a real implementation,
        # you would use tools like Process Monitor or similar
        return []
        
    def _get_registry_operations(self, pid: int) -> List[Dict[str, Any]]:
        """Get registry operations performed by the process"""
        # This is a simplified version. In a real implementation,
        # you would use tools like Process Monitor or similar
        return []
        
    def _get_system_calls(self, pid: int) -> List[Dict[str, Any]]:
        """Get system calls made by the process"""
        # This is a simplified version. In a real implementation,
        # you would use tools like Process Monitor or similar
        return [] 