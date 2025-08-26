
                rule Suspicious_Behaviors {
                    strings:
                        $s1 = "CreateRemoteThread" wide ascii
                        $s2 = "VirtualAlloc" wide ascii
                        $s3 = "WriteProcessMemory" wide ascii
                    condition:
                        any of ($s*)
                }
                