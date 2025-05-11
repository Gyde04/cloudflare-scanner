# Cloudflare IP Scanner

A web application that helps uncover real IP addresses behind Cloudflare's protection using various techniques including DNS history, SSL certificate information, WHOIS data, and subdomain scanning.

## Features

- DNS History Analysis
- SSL Certificate Information Retrieval
- WHOIS Data Lookup
- Subdomain Scanning
- User Agent Rotation
- Enhanced Error Handling

## Requirements

- Python 3.9+
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Gyde04/cloudflare-scanner.git
cd cloudflare-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
./start.sh  # On Windows: python run.py
```

2. Open your web browser and navigate to:
```
http://127.0.0.1:5001
```

3. Enter a domain name in the input field and click "Scan" to begin the analysis.

## Security Notice

This tool is intended for educational and legitimate security research purposes only. Always ensure you have proper authorization before scanning any domain.

## License

MIT License 