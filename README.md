# Cloudflare IP Scanner

A powerful web application designed to help security researchers and system administrators discover real IP addresses behind Cloudflare's protection. This tool employs multiple advanced techniques to attempt to reveal the actual server IP addresses that Cloudflare is protecting.

## 🌟 Key Features

- **DNS History Analysis**: Scans historical DNS records to find previously exposed IP addresses
- **SSL Certificate Information**: Extracts and analyzes SSL certificate data for potential IP leaks
- **WHOIS Data Lookup**: Retrieves and analyzes domain registration information
- **Subdomain Scanning**: Discovers and analyzes subdomains for potential IP leaks
- **User Agent Rotation**: Implements intelligent user agent rotation to avoid detection
- **Enhanced Error Handling**: Robust error handling and retry mechanisms
- **Modern Web Interface**: Clean, responsive UI for easy interaction

## 🔧 Technical Details

- Built with Flask for robust web application handling
- Utilizes multiple Python libraries for comprehensive scanning:
  - `dnspython` for DNS operations
  - `cryptography` for SSL certificate analysis
  - `python-whois` for domain information
  - `requests` for HTTP operations
  - `beautifulsoup4` for HTML parsing

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- pip (Python package manager)

### Installation

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

### Usage

1. Start the application:
```bash
./start.sh  # On Windows: python run.py
```

2. Open your web browser and navigate to:
```
http://127.0.0.1:5001
```

3. Enter a domain name in the input field and click "Scan" to begin the analysis.

## ⚠️ Security Notice

This tool is intended for:
- Educational purposes
- Legitimate security research
- System administration tasks
- Network security assessments

Always ensure you have proper authorization before scanning any domain. Unauthorized scanning may be illegal in some jurisdictions.

## 🔒 Best Practices

- Always obtain permission before scanning any domain
- Respect rate limits and scanning policies
- Use responsibly and ethically
- Keep the tool updated with the latest security patches
- Monitor for any changes in Cloudflare's protection mechanisms

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

This tool is provided for educational and legitimate security research purposes only. The user assumes all responsibility for its use. Always ensure compliance with all applicable laws and regulations. 