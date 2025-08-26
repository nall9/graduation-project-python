import os
import hashlib
import magic
import yara
import pefile
from typing import Dict, Any
import math

class StaticAnalyzer:
    def __init__(self):
        try:
            # Try to initialize magic with mime=True first
            self.mime = magic.Magic(mime=True)
        except Exception:
            try:
                # Fallback to default initialization
                self.mime = magic.Magic()
            except Exception as e:
                print(f"Warning: Could not initialize magic library: {str(e)}")
                self.mime = None
                
        self.yara_rules = self._load_yara_rules()
        
    def _load_yara_rules(self) -> Dict[str, Any]:
        """Load YARA rules for malware detection"""
        rules = {}
        rules_dir = "rules"
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
            # Create a basic YARA rule file if none exists
            with open(os.path.join(rules_dir, "basic_rules.yar"), "w") as f:
                f.write("""
                rule Suspicious_Behaviors {
                    strings:
                        $s1 = "CreateRemoteThread" wide ascii
                        $s2 = "VirtualAlloc" wide ascii
                        $s3 = "WriteProcessMemory" wide ascii
                    condition:
                        any of ($s*)
                }
                """)
        
        for rule_file in os.listdir(rules_dir):
            if rule_file.endswith('.yar'):
                rule_path = os.path.join(rules_dir, rule_file)
                try:
                    rules[rule_file] = yara.compile(rule_path)
                except Exception as e:
                    print(f"Error loading YARA rule {rule_file}: {str(e)}")
        return rules
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform static analysis on the given file"""
        results = {
            'file_info': {},
            'yara_matches': [],
            'pe_analysis': {},
            'entropy': None,
            'suspicious_strings': []
        }
        
        try:
            # Basic file information
            file_info = {
                'size': os.path.getsize(file_path),
                'md5': self._calculate_md5(file_path),
                'sha256': self._calculate_sha256(file_path)
            }
            
            # Add file type if magic is available
            if self.mime:
                try:
                    file_info['type'] = self.mime.from_file(file_path)
                except Exception:
                    file_info['type'] = 'unknown'
            else:
                file_info['type'] = 'unknown'
                
            results['file_info'] = file_info
            
            # YARA rule matching
            for rule_name, rule in self.yara_rules.items():
                matches = rule.match(file_path)
                if matches:
                    results['yara_matches'].extend([
                        {'rule': rule_name, 'match': str(match)}
                        for match in matches
                    ])
            
            # PE file analysis
            if file_path.lower().endswith(('.exe', '.dll')):
                results['pe_analysis'] = self._analyze_pe(file_path)
            
            # Entropy analysis
            results['entropy'] = self._calculate_entropy(file_path)
            
            # Suspicious string analysis
            results['suspicious_strings'] = self._find_suspicious_strings(file_path)
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash of the file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash of the file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE file structure"""
        pe_info = {}
        try:
            pe = pefile.PE(file_path)
            pe_info = {
                'machine_type': hex(pe.FILE_HEADER.Machine),
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'sections': [],
                'imports': [],
                'exports': []
            }
            
            # Analyze sections
            for section in pe.sections:
                pe_info['sections'].append({
                    'name': section.Name.decode().rstrip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'size_of_raw_data': hex(section.SizeOfRawData),
                    'characteristics': hex(section.Characteristics)
                })
            
            # Analyze imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            pe_info['imports'].append(imp.name.decode())
            
            # Analyze exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        pe_info['exports'].append(exp.name.decode())
                        
        except Exception as e:
            pe_info['error'] = str(e)
            
        return pe_info
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of the file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
                
            entropy = 0
            for x in range(256):
                p_x = float(data.count(x))/len(data)
                if p_x > 0:
                    entropy += -p_x * math.log2(p_x)
            return entropy
            
        except Exception:
            return 0.0
    
    def _find_suspicious_strings(self, file_path: str) -> list:
        """Find suspicious strings in the file"""
        suspicious_patterns = [
            b'cmd.exe',
            b'powershell.exe',
            b'http://',
            b'https://',
            b'CreateRemoteThread',
            b'VirtualAlloc',
            b'WriteProcessMemory',
            b'RegCreateKey',
            b'RegSetValue',
            b'ShellExecute'
        ]
        
        found_strings = []
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                for pattern in suspicious_patterns:
                    if pattern in content:
                        found_strings.append(pattern.decode())
        except Exception:
            pass
            
        return found_strings 