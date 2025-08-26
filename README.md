# Malware Classification System

A comprehensive Python-based system for detecting and classifying malware using a combination of static and dynamic analysis, machine learning, and real-time threat intelligence.

## Features

- **Static Analysis**: Analyzes files without execution to detect potential threats
  - YARA rule matching
  - PE file analysis
  - Entropy analysis
  - Suspicious string detection

- **Dynamic Analysis**: Observes malware during execution
  - Process behavior monitoring
  - Network activity tracking
  - File and registry operation monitoring
  - System call analysis

- **Machine Learning Classification**: Uses ML to analyze patterns
  - Feature extraction
  - Random Forest classifier
  - Probability-based detection
  - Model updating capability

- **Real-Time Threat Intelligence**: Continuous threat monitoring
  - Hash-based detection
  - Threat level assessment
  - Caching system
  - External API integration

- **Automated Response**: Rapid threat mitigation
  - File quarantine
  - Detailed reporting
  - Threat level assessment
  - File restoration

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/malware-classifier.git
cd malware-classifier
```

2. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python malware_classifier.py
```

2. Use the GUI to:
   - Select files for analysis
   - View analysis results
   - Monitor real-time threats
   - Manage quarantined files

## Project Structure

```
malware-classifier/
├── malware_classifier.py    # Main application
├── static_analyzer.py       # Static analysis component
├── dynamic_analyzer.py      # Dynamic analysis component
├── ml_classifier.py         # Machine learning component
├── threat_intelligence.py   # Threat intelligence component
├── response_handler.py      # Automated response component
├── requirements.txt         # Project dependencies
├── rules/                  # YARA rules directory
├── models/                 # ML models directory
├── logs/                   # Log files
├── cache/                  # Threat intelligence cache
├── quarantine/             # Quarantined files
└── reports/                # Analysis reports
```

## Configuration

The system can be configured by modifying the following:

- YARA rules in the `rules/` directory
- ML model parameters in `ml_classifier.py`
- Threat intelligence settings in `threat_intelligence.py`
- Response actions in `response_handler.py`

## Security Considerations

- Always run the system in a controlled environment
- Use appropriate permissions for file operations
- Regularly update YARA rules and ML models
- Monitor system logs for suspicious activity

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License



## Screenshot

Here is the main interface of the Malware Classification System:

<img width="1469" height="969" alt="لقطة شاشة 2025-08-26 105849" src="https://github.com/user-attachments/assets/bf0e039e-50d0-4e2d-88e1-d32caf627617" />





This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Always follow proper security protocols and obtain necessary permissions before analyzing potentially malicious files. 
