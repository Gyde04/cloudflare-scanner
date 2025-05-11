from flask import Flask, render_template, request, jsonify
import dns.resolver
import requests
import whois
from datetime import datetime
import socket
import ssl
import OpenSSL
from urllib.parse import urlparse
import concurrent.futures
import random
import time
from requests.exceptions import RequestException
import json
import re
from bs4 import BeautifulSoup

app = Flask(__name__)

# List of common user agents to rotate through
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def make_request(url, headers=None, verify=True):
    """Make a request with rotating user agents and proper headers"""
    if headers is None:
        headers = {}
    
    headers.update({
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
        'TE': 'Trailers',
        'DNT': '1'
    })
    
    try:
        response = requests.get(
            url, 
            headers=headers, 
            timeout=10, 
            allow_redirects=True,
            verify=verify
        )
        return response
    except RequestException as e:
        return None

def get_dns_history(domain):
    """Get historical DNS records using multiple methods"""
    results = []
    
    # Try different DNS record types
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results.extend([f"{record_type}: {str(rdata)}" for rdata in answers])
        except:
            continue
    
    # Try to get DNS history from common subdomains
    common_subdomains = ['www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'ns4']
    for subdomain in common_subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            results.extend([f"Subdomain {full_domain}: {str(rdata)}" for rdata in answers])
        except:
            continue
    
    return results

def get_ssl_cert_info(domain):
    """Get SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': cert.get('issuer', []),
                    'subject': cert.get('subject', []),
                    'version': cert.get('version', ''),
                    'notBefore': cert.get('notBefore', ''),
                    'notAfter': cert.get('notAfter', ''),
                    'serialNumber': cert.get('serialNumber', '')
                }
    except:
        return None

def get_whois_info(domain):
    """Get WHOIS information"""
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers,
            'status': w.status,
            'emails': w.emails,
            'dnssec': w.dnssec
        }
    except:
        return None

def scan_common_subdomains(domain):
    """Scan for common subdomains"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'ns4',
        'admin', 'blog', 'dev', 'staging', 'test', 'api', 'cdn', 'shop',
        'store', 'support', 'help', 'docs', 'beta', 'alpha', 'secure',
        'app', 'apps', 'cloud', 'cloudflare', 'cp', 'cpanel', 'dashboard',
        'db', 'database', 'demo', 'dev', 'developer', 'development',
        'email', 'exchange', 'files', 'forum', 'forums', 'git', 'github',
        'gitlab', 'hosting', 'imap', 'jenkins', 'lab', 'labs', 'login',
        'manage', 'management', 'monitor', 'monitoring', 'mysql', 'new',
        'news', 'old', 'portal', 'remote', 'server', 'service', 'services',
        'shop', 'site', 'sites', 'smtp', 'sql', 'ssh', 'staff', 'stage',
        'staging', 'start', 'stat', 'static', 'stats', 'status', 'stg',
        'support', 'sys', 'system', 'test', 'testing', 'tools', 'upload',
        'uploads', 'vpn', 'web', 'webmail', 'wiki', 'work', 'workshop',
        'www', 'www2', 'www3', 'www4', 'www5', 'www6', 'www7', 'www8',
        'www9', 'www10'
    ]
    results = []
    
    def check_subdomain(subdomain):
        try:
            full_domain = f"{subdomain}.{domain}"
            ip = socket.gethostbyname(full_domain)
            return {'subdomain': full_domain, 'ip': ip}
        except:
            return None

    # Use ThreadPoolExecutor for parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain, subdomain): subdomain 
            for subdomain in common_subdomains
        }
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                results.append(result)
                # Add a small delay to avoid rate limiting
                time.sleep(0.1)
    
    return results

def check_cloudflare(domain):
    """Check if the domain is using Cloudflare and gather additional information"""
    try:
        response = make_request(f"https://{domain}")
        if response:
            headers = response.headers
            html = response.text
            
            # Check for Cloudflare specific headers and content
            cf_headers = {
                'Server': headers.get('Server', ''),
                'CF-RAY': headers.get('CF-RAY', ''),
                'CF-Cache-Status': headers.get('CF-Cache-Status', ''),
                'CF-Connecting-IP': headers.get('CF-Connecting-IP', ''),
                'CF-IPCountry': headers.get('CF-IPCountry', ''),
                'CF-Visitor': headers.get('CF-Visitor', ''),
                'CF-WAN-Error': headers.get('CF-WAN-Error', '')
            }
            
            # Check for Cloudflare specific content in HTML
            cf_content = False
            if html:
                soup = BeautifulSoup(html, 'html.parser')
                cf_content = bool(soup.find('script', string=re.compile('cloudflare')))
            
            return {
                'is_cloudflare': 'cloudflare' in str(headers).lower() or cf_content,
                'headers': cf_headers,
                'has_cf_content': cf_content
            }
    except:
        pass
    return {'is_cloudflare': False}

def find_real_ip(domain):
    """Attempt to find the real IP address using multiple methods"""
    results = []
    
    # Method 1: Try direct IP resolution
    try:
        ip = socket.gethostbyname(domain)
        results.append({'method': 'Direct DNS', 'ip': ip})
    except:
        pass
    
    # Method 2: Try common subdomains
    subdomains = scan_common_subdomains(domain)
    if subdomains:
        results.extend([{'method': 'Subdomain', 'ip': sub['ip'], 'source': sub['subdomain']} for sub in subdomains])
    
    # Method 3: Check SSL certificate
    ssl_info = get_ssl_cert_info(domain)
    if ssl_info and 'subject' in ssl_info:
        for subject in ssl_info['subject']:
            if isinstance(subject, tuple) and len(subject) == 2:
                if subject[0] == 'commonName':
                    try:
                        ip = socket.gethostbyname(subject[1])
                        results.append({'method': 'SSL Certificate', 'ip': ip, 'source': subject[1]})
                    except:
                        pass
    
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Parse the domain from the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Remove 'www.' if present
    if domain.startswith('www.'):
        domain = domain[4:]
    
    try:
        # Get Cloudflare information
        cf_info = check_cloudflare(domain)
        
        # Get real IP information
        real_ip_info = find_real_ip(domain)
        
        results = {
            'domain': domain,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'cloudflare_info': cf_info,
            'real_ip_info': real_ip_info,
            'dns_records': get_dns_history(domain),
            'ssl_cert': get_ssl_cert_info(domain),
            'whois_info': get_whois_info(domain),
            'subdomains': scan_common_subdomains(domain)
        }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'An error occurred while scanning the website. The website might be blocking automated requests.'
        }), 500

if __name__ == '__main__':
    app.run(debug=True) 