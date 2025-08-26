# graduation-project-python
A Python-based graduation project focused on network scanning and security analysis.
# Malware Classification System

A graduation project focused on building an **AI-based Malware Classification System**.  
The system combines **static and dynamic analysis**, **machine learning classification**, and **threat intelligence** to detect and classify malware.  

## Features
- **Static Analysis**: Extracts file metadata, strings, headers, and YARA rule matches.  
- **Dynamic Analysis**: Monitors runtime behavior (processes, network activity, file and registry changes).  
- **Machine Learning Classifier**: Uses entropy, file size, and suspicious strings to calculate a risk score and classify files.  
- **Threat Intelligence**: Checks file hashes against reputation data and caches results.  
- **Graphical User Interface (GUI)**: Built with Tkinter, including tabs for each analysis module, dark/light themes, and dashboards.  

## Tools & Technologies
- Python 3  
- Tkinter (GUI)  
- Scikit-learn / ML libraries (planned)  
- SQLite (for storing analysis results)  
- YARA rules (for static detection)  
- psutil, magic, matplotlib  

## How to Run
1. Clone this repository:
   ```bash
   git clone https://github.com/nall9/graduation-project-python.git
   cd graduation-project-python
pip install -r requirements.txt
python malware_classifier.py
