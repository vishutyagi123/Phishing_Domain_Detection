import streamlit as st
import warnings

warnings.filterwarnings('ignore')

from urllib.parse import urlparse, parse_qs
import requests, pickle, whois, datetime, pandas as pd, time, re, socket, json, hashlib
from ipaddress import ip_address, IPv4Address, IPv6Address
from bs4 import BeautifulSoup
from ipwhois.asn import IPASN
from ipwhois.net import Net
from sklearn.preprocessing import FunctionTransformer
import numpy as np
import dns.resolver
import ssl
import ipaddress

# Page configuration
st.set_page_config(
    page_title="Phishing Domain Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for attractive styling
st.markdown("""
<style>
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Main container styling */
    .main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 0;
    }

    /* Fix text visibility in input - CRITICAL */
    .stTextInput input {
        color: #1a202c !important;
        font-weight: 500 !important;
        background: white !important;
    }

    .stTextInput input::placeholder {
        color: #a0aec0 !important;
        opacity: 0.7 !important;
    }

    /* Make sure text is visible while typing */
    .stTextInput input:focus {
        color: #1a202c !important;
    }

    /* Hero section */
    .hero-section {
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.95) 0%, rgba(118, 75, 162, 0.95) 100%);
        padding: 2.5rem 2rem;
        border-radius: 16px;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        backdrop-filter: blur(10px);
    }

    .hero-title {
        font-size: 2.8rem;
        font-weight: 800;
        color: white;
        margin-bottom: 0.8rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        letter-spacing: -0.5px;
    }

    .hero-subtitle {
        font-size: 1.1rem;
        color: rgba(255,255,255,0.9);
        margin-bottom: 0;
        font-weight: 400;
    }

    /* Input section label */
    .input-label {
        color: white;
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
        display: block;
    }

    /* Input section */
    .stTextInput > div > div > input {
        border-radius: 12px !important;
        padding: 1rem 1.3rem !important;
        font-size: 1rem !important;
        border: 2px solid rgba(255,255,255,0.2) !important;
        background: white !important;
        transition: all 0.3s ease !important;
        color: #1a202c !important;
        font-weight: 500 !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: #667eea !important;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2) !important;
        outline: none !important;
        background: white !important;
        color: #1a202c !important;
    }

    /* Button styling */
    .stButton > button {
        width: 100%;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 0.75rem 2rem;
        border-radius: 12px;
        border: none;
        font-size: 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        cursor: pointer;
    }

    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
        background: linear-gradient(135deg, #7690f0 0%, #8658b2 100%);
    }

    .stButton > button:active {
        transform: translateY(0px);
    }

    /* Result cards */
    .result-card {
        padding: 2rem;
        border-radius: 16px;
        margin: 1.5rem 0;
        box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        animation: slideInUp 0.5s ease-out;
    }

    .safe-card {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        border-left: 5px solid #00d4ff;
    }

    .danger-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        border-left: 5px solid #ff0844;
    }

    .result-icon {
        font-size: 3.5rem;
        margin-bottom: 0.8rem;
    }

    .result-title {
        font-size: 2rem;
        font-weight: 700;
        color: white;
        margin-bottom: 1rem;
        letter-spacing: -0.3px;
    }

    .result-text {
        font-size: 1.05rem;
        color: rgba(255,255,255,0.95);
        line-height: 1.7;
    }

    .result-text p {
        margin-bottom: 0.7rem;
    }

    .result-text strong {
        font-weight: 600;
    }

    /* Info cards */
    .info-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        transition: all 0.3s ease;
        border: 1px solid rgba(0,0,0,0.05);
    }

    .info-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 4px 20px rgba(0,0,0,0.12);
    }

    .info-title {
        color: #667eea;
        font-size: 1.25rem;
        font-weight: 700;
        margin-bottom: 0.6rem;
    }

    .info-text {
        color: #4a5568;
        font-size: 0.95rem;
        line-height: 1.6;
    }

    /* Statistics container */
    .stat-container {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        border: 1px solid rgba(0,0,0,0.05);
    }

    .stat-number {
        font-size: 2.2rem;
        font-weight: 800;
        color: #667eea;
        margin-bottom: 0.4rem;
    }

    .stat-label {
        font-size: 0.85rem;
        color: #718096;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-weight: 600;
    }

    /* Section headers */
    .main h2 {
        color: white;
        font-weight: 700;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }

    .main h3 {
        color: white;
        font-weight: 600;
        margin-bottom: 1rem;
    }

    /* Animations */
    @keyframes slideInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }

    [data-testid="stSidebar"] h3 {
        color: white;
        font-weight: 700;
    }

    [data-testid="stSidebar"] p, [data-testid="stSidebar"] strong {
        color: rgba(255,255,255,0.95);
    }

    /* Feature list */
    .feature-item {
        display: flex;
        align-items: center;
        padding: 0.7rem;
        margin: 0.4rem 0;
        background: rgba(255,255,255,0.15);
        border-radius: 8px;
        color: white;
        font-size: 0.9rem;
        transition: all 0.2s ease;
    }

    .feature-item:hover {
        background: rgba(255,255,255,0.25);
        transform: translateX(5px);
    }

    .feature-icon {
        font-size: 1.3rem;
        margin-right: 0.8rem;
    }

    /* Tips section */
    .main p {
        color: white;
        line-height: 1.6;
    }

    /* Alert/Error styling */
    .stAlert {
        border-radius: 12px;
    }

    /* Warning box */
    .warning-box {
        background: rgba(255, 193, 7, 0.2);
        border-left: 4px solid #ffc107;
        padding: 1rem;
        border-radius: 8px;
        color: white;
        margin: 1rem 0;
    }

    /* Threat intelligence badges */
    .threat-badge {
        display: inline-block;
        padding: 0.4rem 0.8rem;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 600;
        margin: 0.3rem;
    }

    .badge-safe {
        background: rgba(76, 175, 80, 0.2);
        color: #4caf50;
        border: 1px solid #4caf50;
    }

    .badge-threat {
        background: rgba(244, 67, 54, 0.2);
        color: #f44336;
        border: 1px solid #f44336;
    }

    .badge-unknown {
        background: rgba(255, 152, 0, 0.2);
        color: #ff9800;
        border: 1px solid #ff9800;
    }
</style>
""", unsafe_allow_html=True)


# =======================
# URL VALIDATION
# =======================

def is_valid_url(url):
    """
    Validate if the input is a proper URL
    Returns: (is_valid, cleaned_url, error_message)
    """
    try:
        # Remove whitespace
        url = url.strip()

        # Check if empty
        if not url:
            return False, None, "URL cannot be empty"

        # Add http:// if no scheme provided
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'http://' + url

        # Parse the URL
        parsed = urlparse(url)

        # Check if netloc (domain) exists
        if not parsed.netloc:
            return False, None, "Invalid URL format - no domain found"

        # Check for valid domain pattern
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

        if not re.match(domain_pattern, parsed.netloc):
            # Check if it might be localhost or IP with port
            if ':' in parsed.netloc:
                domain_part = parsed.netloc.split(':')[0]
                if domain_part == 'localhost' or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_part):
                    return True, url, None
            return False, None, "Invalid domain format"

        # Check for minimum domain length
        if len(parsed.netloc) < 3:
            return False, None, "Domain name too short"

        # Check if it looks like a file path
        if url.startswith(('/', '\\', 'C:', 'D:', 'E:')):
            return False, None, "This looks like a file path, not a URL"

        # Check if it's just text without dots (except localhost)
        if '.' not in parsed.netloc and parsed.netloc != 'localhost':
            return False, None, "Invalid URL - must contain a domain with extension (e.g., .com, .org)"

        return True, url, None

    except Exception as e:
        return False, None, f"Invalid URL format: {str(e)}"


# =======================
# FREE THREAT INTELLIGENCE APIs (No API Key Required)
# =======================

def check_urlscan_io(url):
    """
    Check URL using URLScan.io API (Free public API - NO KEY REQUIRED)
    """
    try:
        # Search for existing scans
        search_url = f"https://urlscan.io/api/v1/search/?q=page.url:{url}"
        headers = {"Content-Type": "application/json"}

        response = requests.get(search_url, headers=headers, timeout=10)

        if response.status_code == 200:
            result = response.json()

            if result.get('total', 0) > 0:
                latest_scan = result['results'][0]
                verdict = latest_scan.get('verdicts', {})
                overall = verdict.get('overall', {})

                return {
                    "status": "success",
                    "score": overall.get('score', 0),
                    "malicious": overall.get('malicious', False),
                    "categories": overall.get('categories', []),
                    "brands": overall.get('brands', [])
                }
            else:
                return {
                    "status": "success",
                    "message": "No previous scans found",
                    "malicious": False,
                    "score": 0
                }

        return {"status": "error", "message": "Failed to check URLScan.io"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_phishtank(url):
    """
    Check URL against PhishTank database (Free API - NO KEY REQUIRED)
    """
    try:
        api_url = "http://checkurl.phishtank.com/checkurl/"

        data = {
            "url": url,
            "format": "json"
        }

        response = requests.post(api_url, data=data, timeout=10)

        if response.status_code == 200:
            result = response.json()

            if result.get('results'):
                is_phish = result['results'].get('in_database', False)
                is_valid = result['results'].get('valid', False)

                return {
                    "status": "success",
                    "is_phishing": is_phish and is_valid,
                    "verified": result['results'].get('verified', False),
                    "phish_id": result['results'].get('phish_id', None)
                }

        return {"status": "error", "message": "Failed to check PhishTank"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_google_transparency_report(url):
    """
    Check if domain is in Google's Safe Browsing transparency report
    This is a passive check using publicly available data
    """
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc

        # Check if domain looks suspicious based on common patterns
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'[a-z0-9]{20,}',  # Very long random string
            r'\.tk$|\.ml$|\.ga$|\.cf$|\.gq$',  # Free TLDs often used for phishing
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return {
                    "status": "warning",
                    "suspicious_pattern": True,
                    "message": "Domain contains suspicious patterns"
                }

        return {
            "status": "success",
            "suspicious_pattern": False
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_openphish(url):
    """
    Check against OpenPhish free feed (community phishing feed)
    """
    try:
        # OpenPhish provides a public feed
        feed_url = "https://openphish.com/feed.txt"

        response = requests.get(feed_url, timeout=10)

        if response.status_code == 200:
            phishing_urls = response.text.split('\n')

            # Check if our URL is in the feed
            is_phishing = url in phishing_urls or any(url.startswith(phish_url) for phish_url in phishing_urls[:100])

            return {
                "status": "success",
                "is_phishing": is_phishing,
                "feed_size": len(phishing_urls)
            }

        return {"status": "error", "message": "Failed to fetch OpenPhish feed"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_all_free_threat_intelligence(url):
    """
    Check URL against all FREE threat intelligence sources
    """
    results = {
        "phishtank": check_phishtank(url),
        "urlscan": check_urlscan_io(url),
        "google_patterns": check_google_transparency_report(url),
        "openphish": check_openphish(url)
    }

    return results


# Load models (with better error handling)
@st.cache_resource
def load_models():
    try:
        # Try multiple possible paths
        possible_paths = [
            (".venv/src/pipeline.pkl", ".venv/src/features.pkl"),
            ("src/pipeline.pkl", "src/features.pkl"),
            ("pipeline.pkl", "features.pkl"),
        ]

        for pipeline_path, features_path in possible_paths:
            try:
                pipeline = pickle.load(open(pipeline_path, 'rb'))
                features = pickle.load(open(features_path, 'rb'))
                return pipeline, features
            except FileNotFoundError:
                continue

        return None, None
    except Exception as e:
        st.warning(f"Model loading note: {str(e)}")
        return None, None


pipeline, features = load_models()


# Helper functions (keeping all your original functions)
def parse(url):
    return urlparse(url)


def fetching_domain_from_ip(parsing):
    domain = parsing.netloc
    try:
        if isinstance(ip_address(parsing.netloc), (IPv4Address, IPv6Address)):
            parsing = parsing._replace(netloc=socket.gethostbyaddr(parsing.netloc)[0].split('.', 1)[-1])
    except Exception as e:
        parsing = parsing._replace(netloc=domain[4:] if domain.startswith('www.') else domain)
    return parsing


def count_vowels(text):
    vowels = "aeiouAEIOU"
    return sum(1 for char in text if char in vowels)


def symbols_count(url):
    symbols = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
    return [len(re.findall(r'\{}'.format(i), url)) for i in symbols]


def domain_in_ip(parsing):
    try:
        ip = ipaddress.ip_address(parsing.netloc)
        return 1
    except ValueError:
        return 0


def get_file_name(parsing):
    import os
    return os.path.basename(parsing.path)


def is_tld_in_params(url, parsing):
    query_params = parse_qs(parsing.query)
    for param_name, param_value in query_params.items():
        for value in param_value:
            if "." in value:
                return 1
    return 0


def get_basic_domain_info(url):
    """Get basic domain information without heavy API calls"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        info = {
            "has_https": parsed.scheme == "https",
            "domain_length": len(domain),
            "has_ip": bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
            "subdomain_count": len(domain.split('.')) - 2,
            "suspicious_tld": domain.endswith(('.tk', '.ml', '.ga', '.cf', '.gq')),
        }

        return info
    except:
        return {}


# Main App
def main():
    # Hero Section
    st.markdown("""
    <div class="hero-section">
        <div class="hero-title">🛡️ Phishing Domain Detector</div>
        <div class="hero-subtitle">Free Threat Intelligence + AI Protection</div>
    </div>
    """, unsafe_allow_html=True)

    # Main content area
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown('<p class="input-label">🔍 Enter URL to Analyze</p>', unsafe_allow_html=True)
        url_input = st.text_input(
            "URL",
            placeholder="https://example.com",
            label_visibility="collapsed",
            key="url_input"
        )

        analyze_button = st.button("🚀 Analyze URL", use_container_width=True)

        if analyze_button:
            if not url_input or url_input.strip() == "":
                st.markdown("""
                <div class="warning-box">
                    ⚠️ <strong>Please enter a URL</strong><br>
                    Enter a website URL in the field above to check if it's safe or potentially malicious.
                </div>
                """, unsafe_allow_html=True)
            else:
                # Validate URL
                is_valid, url_to_check, error_message = is_valid_url(url_input)

                if not is_valid:
                    st.markdown(f"""
                    <div class="warning-box">
                        ⚠️ <strong>Please enter a valid URL</strong><br>
                        {error_message}<br><br>
                        <strong>Examples of valid URLs:</strong><br>
                        • https://www.example.com<br>
                        • http://example.com<br>
                        • example.com (will be converted to http://example.com)<br>
                        • www.example.org
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    with st.spinner('🔬 Running comprehensive analysis...'):
                        try:
                            # STEP 1: Check FREE threat intelligence sources (PRIORITY)
                            st.info("🌐 Checking free threat intelligence databases...")
                            threat_results = check_all_free_threat_intelligence(url_to_check)

                            # STEP 2: Get basic domain info
                            basic_info = get_basic_domain_info(url_to_check)

                            # STEP 3: Analyze threat intelligence results
                            threat_count = 0
                            threat_sources = []
                            threat_details = []

                            # PhishTank
                            if threat_results['phishtank'].get('status') == 'success':
                                if threat_results['phishtank'].get('is_phishing'):
                                    threat_count += 1
                                    threat_sources.append("PhishTank")
                                    if threat_results['phishtank'].get('verified'):
                                        threat_details.append("Verified phishing site in PhishTank database")

                            # URLScan
                            if threat_results['urlscan'].get('status') == 'success':
                                if threat_results['urlscan'].get('malicious'):
                                    threat_count += 1
                                    threat_sources.append("URLScan.io")
                                    categories = threat_results['urlscan'].get('categories', [])
                                    if categories:
                                        threat_details.append(f"URLScan categories: {', '.join(categories)}")

                            # OpenPhish
                            if threat_results['openphish'].get('status') == 'success':
                                if threat_results['openphish'].get('is_phishing'):
                                    threat_count += 1
                                    threat_sources.append("OpenPhish")
                                    threat_details.append("Listed in OpenPhish community feed")

                            # Google Patterns
                            if threat_results['google_patterns'].get('suspicious_pattern'):
                                threat_count += 0.5  # Half point for pattern matching
                                threat_sources.append("Pattern Analysis")
                                threat_details.append("Contains suspicious URL patterns")

                            # Basic domain checks
                            if basic_info.get('has_ip'):
                                threat_count += 0.5
                                threat_sources.append("IP Address Detection")
                                threat_details.append("URL uses IP address instead of domain name")

                            if basic_info.get('suspicious_tld'):
                                threat_count += 0.5
                                threat_sources.append("TLD Analysis")
                                threat_details.append("Uses free TLD commonly associated with phishing")

                            if not basic_info.get('has_https'):
                                threat_count += 0.3
                                threat_sources.append("HTTPS Check")
                                threat_details.append("No HTTPS encryption detected")

                            st.markdown("---")

                            # DETERMINE FINAL VERDICT based on free tools
                            is_dangerous = threat_count >= 1.0

                            if is_dangerous:
                                # PHISHING/THREAT DETECTED
                                confidence = min(95, 60 + (threat_count * 10))

                                st.markdown(f"""
                                <div class="result-card danger-card">
                                    <div class="result-icon">⚠️</div>
                                    <div class="result-title">THREAT DETECTED - DO NOT PROCEED</div>
                                    <div class="result-text">
                                        <p><strong>URL:</strong> {url_to_check}</p>
                                        <p><strong>Confidence:</strong> {confidence:.0f}% likely to be malicious</p>
                                        <p><strong>⚠️ Flagged by {len(set(threat_sources))} source(s):</strong> {", ".join(set(threat_sources))}</p>
                                        <p><strong>Threat Details:</strong></p>
                                        <ul>
                                            {"".join([f"<li>{detail}</li>" for detail in threat_details])}
                                        </ul>
                                        <p>🔒 <strong>Recommendation:</strong> Do NOT visit this website or enter any personal information. This URL has been identified as potentially malicious.</p>
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                # APPEARS SAFE
                                st.markdown(f"""
                                <div class="result-card safe-card">
                                    <div class="result-icon">✅</div>
                                    <div class="result-title">No Immediate Threats Detected</div>
                                    <div class="result-text">
                                        <p><strong>URL:</strong> {url_to_check}</p>
                                        <p>This URL was not found in any known phishing databases.</p>
                                        <p><strong>Security Indicators:</strong></p>
                                        <ul>
                                            <li>{"✅" if basic_info.get("has_https") else "⚠️"} HTTPS: {"Enabled" if basic_info.get("has_https") else "Not detected"}</li>
                                            <li>{"✅" if not basic_info.get("has_ip") else "⚠️"} Domain: {"Uses domain name" if not basic_info.get("has_ip") else "Uses IP address"}</li>
                                            <li>{"✅" if not basic_info.get("suspicious_tld") else "⚠️"} TLD: {"Standard TLD" if not basic_info.get("suspicious_tld") else "Free/Suspicious TLD"}</li>
                                        </ul>
                                        <p>⚠️ <strong>Note:</strong> While no immediate threats were detected, always exercise caution when entering personal information online.</p>
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)

                            # Show threat intelligence details
                            st.markdown("### 🌐 Threat Intelligence Report")

                            col_ti1, col_ti2, col_ti3, col_ti4 = st.columns(4)

                            with col_ti1:
                                phish_status = threat_results['phishtank']
                                if phish_status.get('status') == 'success':
                                    is_phish = phish_status.get('is_phishing', False)
                                    badge_class = 'badge-threat' if is_phish else 'badge-safe'
                                    status_text = '⚠️ Threat' if is_phish else '✅ Safe'
                                else:
                                    badge_class = 'badge-unknown'
                                    status_text = '? Error'

                                st.markdown(f"""
                                <div class="stat-container">
                                    <div class="threat-badge {badge_class}">{status_text}</div>
                                    <div class="stat-label">PhishTank</div>
                                </div>
                                """, unsafe_allow_html=True)

                            with col_ti2:
                                urlscan_status = threat_results['urlscan']
                                if urlscan_status.get('status') == 'success':
                                    is_malicious = urlscan_status.get('malicious', False)
                                    badge_class = 'badge-threat' if is_malicious else 'badge-safe'
                                    status_text = '⚠️ Threat' if is_malicious else '✅ Safe'
                                else:
                                    badge_class = 'badge-unknown'
                                    status_text = '? No Data'

                                st.markdown(f"""
                                <div class="stat-container">
                                    <div class="threat-badge {badge_class}">{status_text}</div>
                                    <div class="stat-label">URLScan.io</div>
                                </div>
                                """, unsafe_allow_html=True)

                            with col_ti3:
                                openphish_status = threat_results['openphish']
                                if openphish_status.get('status') == 'success':
                                    is_phish = openphish_status.get('is_phishing', False)
                                    badge_class = 'badge-threat' if is_phish else 'badge-safe'
                                    status_text = '⚠️ Listed' if is_phish else '✅ Clean'
                                else:
                                    badge_class = 'badge-unknown'
                                    status_text = '? Error'

                                st.markdown(f"""
                                <div class="stat-container">
                                    <div class="threat-badge {badge_class}">{status_text}</div>
                                    <div class="stat-label">OpenPhish</div>
                                </div>
                                """, unsafe_allow_html=True)

                            with col_ti4:
                                pattern_status = threat_results['google_patterns']
                                is_suspicious = pattern_status.get('suspicious_pattern', False)
                                badge_class = 'badge-threat' if is_suspicious else 'badge-safe'
                                status_text = '⚠️ Suspicious' if is_suspicious else '✅ Normal'

                                st.markdown(f"""
                                <div class="stat-container">
                                    <div class="threat-badge {badge_class}">{status_text}</div>
                                    <div class="stat-label">Pattern Check</div>
                                </div>
                                """, unsafe_allow_html=True)

                            # Show URL characteristics
                            st.markdown("### 📊 URL Characteristics")

                            col_a, col_b, col_c = st.columns(3)

                            with col_a:
                                st.markdown(f"""
                                <div class="stat-container">
                                    <div class="stat-number">{'🔒' if basic_info.get('has_https') else '🔓'}</div>
                                    <div class="stat-label">HTTPS</div>
                                </div>
                                """, unsafe_allow_html=True)

                            with col_b:
                                st.markdown(f"""
                                <div class="stat-container">
                                    <div class="stat-number">{basic_info.get('domain_length', 0)}</div>
                                    <div class="stat-label">Domain Length</div>
                                </div>
                                """, unsafe_allow_html=True)

                            with col_c:
                                st.markdown(f"""
                                <div class="stat-container">
                                    <div class="stat-number">{basic_info.get('subdomain_count', 0)}</div>
                                    <div class="stat-label">Subdomains</div>
                                </div>
                                """, unsafe_allow_html=True)

                        except Exception as e:
                            st.error(f"❌ Error analyzing URL: {str(e)}")

    with col2:
        st.markdown("### 📈 Detection Stats")
        st.markdown("""
        <div class="stat-container">
            <div class="stat-number">4</div>
            <div class="stat-label">Free Threat Sources</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="stat-container" style="margin-top: 1rem;">
            <div class="stat-number">100%</div>
            <div class="stat-label">No API Keys Needed</div>
        </div>
        """, unsafe_allow_html=True)

    # Information Section
    st.markdown("---")
    st.markdown("## 🔒 Multi-Layer Protection (All FREE)")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class="info-card">
            <div class="info-title">🌐 Free Threat Intelligence</div>
            <div class="info-text">
                <strong>PhishTank:</strong> Community-driven phishing database<br>
                <strong>URLScan.io:</strong> Public URL scanner and analyzer<br>
                <strong>OpenPhish:</strong> Free phishing feed<br>
                <strong>Pattern Analysis:</strong> Suspicious URL pattern detection
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="info-card">
            <div class="info-title">🔍 What We Check</div>
            <div class="info-text">
                ✅ Known phishing databases<br>
                ✅ URL structure and patterns<br>
                ✅ HTTPS/SSL status<br>
                ✅ Suspicious TLDs<br>
                ✅ IP address usage<br>
                ✅ Domain characteristics
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Tips Section
    st.markdown("---")
    st.markdown("## 💡 Security Best Practices")

    col1, col2 = st.columns(2)

    with col1:
        tips_1 = [
            "✅ Always verify the URL before clicking",
            "✅ Look for HTTPS and valid SSL certificates",
            "✅ Be cautious of urgent or threatening messages",
            "✅ Never share passwords via email or suspicious sites"
        ]
        for tip in tips_1:
            st.markdown(tip)

    with col2:
        tips_2 = [
            "✅ Use two-factor authentication when available",
            "✅ Keep software and browsers updated",
            "✅ Hover over links to see actual destination",
            "✅ Report suspicious emails to your IT team"
        ]
        for tip in tips_2:
            st.markdown(tip)


# Sidebar
with st.sidebar:
    st.markdown("### 🔧 Detection Features")

    features_list = [
        "🆓 100% Free Tools",
        "🌐 4 Threat Databases",
        "⚡ Real-time Checking",
        "🔍 Pattern Analysis",
        "🔒 HTTPS Verification",
        "🎯 No API Keys Required",
        "📊 Instant Results",
        "🛡️ Multi-layer Detection"
    ]

    for feature in features_list:
        st.markdown(f"""
        <div class="feature-item">
            <span class="feature-icon">{feature.split()[0]}</span>
            <span>{' '.join(feature.split()[1:])}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📊 Free Data Sources")
    st.markdown("""
    - **PhishTank**: Community phishing database
    - **URLScan.io**: Public URL analysis
    - **OpenPhish**: Community phishing feed
    - **Pattern Detection**: Built-in analysis
    """)

    st.markdown("---")
    st.markdown("### 💡 Why Free Tools?")
    st.markdown("""
    This tool uses only **free, public threat intelligence sources** so you can:
    - ✅ Use it without API keys
    - ✅ Get instant results
    - ✅ No setup required
    - ✅ Access anytime
    """)


if __name__ == "__main__":
    main()
