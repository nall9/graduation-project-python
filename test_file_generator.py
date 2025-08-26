import os
import random
import string

def generate_suspicious_file(filename="test_suspicious.exe"):
    """
    Generate a test file with suspicious patterns for malware analysis.
    This is for testing purposes only and doesn't contain actual malicious code.
    """
    # Create some suspicious-looking strings
    suspicious_strings = [
        "cmd.exe /c",
        "powershell.exe -enc",
        "http://malicious.com",
        "C:\\Windows\\System32",
        "CreateRemoteThread",
        "VirtualAlloc",
        "WriteProcessMemory",
        "RegCreateKey",
        "WinExec",
        "ShellExecute",
        "GetAsyncKeyState",  # Common in keyloggers
        "SetWindowsHookEx",  # Common in spyware
        "InternetOpenUrl",
        "URLDownloadToFile",
        "WinHttpSendRequest",
        "CryptAcquireContext",
        "CryptEncrypt",
        "CryptDecrypt",
        "CreateFile",
        "WriteFile",
        "ReadFile",
        "DeleteFile",
        "MoveFile",
        "CopyFile",
        "FindFirstFile",
        "FindNextFile",
        "GetSystemDirectory",
        "GetWindowsDirectory",
        "GetTempPath",
        "GetTempFileName",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "OpenProcess",
        "TerminateProcess",
        "CreateProcess",
        "CreateThread",
        "Sleep",
        "GetTickCount",
        "GetSystemTime",
        "GetLocalTime",
        "GetFileTime",
        "SetFileTime",
        "GetFileAttributes",
        "SetFileAttributes",
        "GetFileSize",
        "GetFileType",
        "GetFileInformationByHandle",
        "GetFileInformationByHandleEx",
        "GetFileInformationByHandleW",
        "GetFileInformationByHandleExW",
        "GetFileInformationByHandleA",
        "GetFileInformationByHandleExA",
        "GetFileInformationByHandleEx2",
        "GetFileInformationByHandleEx2W",
        "GetFileInformationByHandleEx2A",
        "GetFileInformationByHandleEx3",
        "GetFileInformationByHandleEx3W",
        "GetFileInformationByHandleEx3A",
        "GetFileInformationByHandleEx4",
        "GetFileInformationByHandleEx4W",
        "GetFileInformationByHandleEx4A",
        "GetFileInformationByHandleEx5",
        "GetFileInformationByHandleEx5W",
        "GetFileInformationByHandleEx5A",
        "GetFileInformationByHandleEx6",
        "GetFileInformationByHandleEx6W",
        "GetFileInformationByHandleEx6A",
        "GetFileInformationByHandleEx7",
        "GetFileInformationByHandleEx7W",
        "GetFileInformationByHandleEx7A",
        "GetFileInformationByHandleEx8",
        "GetFileInformationByHandleEx8W",
        "GetFileInformationByHandleEx8A",
        "GetFileInformationByHandleEx9",
        "GetFileInformationByHandleEx9W",
        "GetFileInformationByHandleEx9A",
        "GetFileInformationByHandleEx10",
        "GetFileInformationByHandleEx10W",
        "GetFileInformationByHandleEx10A",
    ]

    # Generate random content
    content = bytearray()
    
    # Add some random bytes
    for _ in range(1000):
        content.extend(random.randint(0, 255).to_bytes(1, byteorder='big'))
    
    # Add suspicious strings
    for suspicious_string in suspicious_strings:
        content.extend(suspicious_string.encode())
        content.extend(random.randint(0, 255).to_bytes(1, byteorder='big'))
    
    # Add some PE-like headers (not a real PE file, just for testing)
    pe_header = b'MZ' + b'\x00' * 58 + b'PE\x00\x00'
    content = pe_header + content[len(pe_header):]
    
    # Write the file
    with open(filename, 'wb') as f:
        f.write(content)
    
    print(f"Generated test file: {filename}")
    print(f"File size: {len(content)} bytes")
    return filename

if __name__ == "__main__":
    # Generate a test file
    test_file = generate_suspicious_file()
    print("\nYou can now use this file to test the malware classification system.")
    print("Note: This is a test file and doesn't contain actual malicious code.") 