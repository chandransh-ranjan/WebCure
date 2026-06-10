"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗    ██╗███████╗██████╗  ██████╗██╗   ██╗██████╗ ███████╗               ║
║   ██║    ██║██╔════╝██╔══██╗██╔════╝██║   ██║██╔══██╗██╔════╝               ║
║   ██║ █╗ ██║█████╗  ██████╔╝██║     ██║   ██║██████╔╝█████╗                 ║
║   ██║███╗██║██╔══╝  ██╔══██╗██║     ██║   ██║██╔══██╗██╔══╝                 ║
║   ╚███╔███╔╝███████╗██████╔╝╚██████╗╚██████╔╝██║  ██║███████╗               ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝               ║
║                                                                              ║
║   Project  : WebCure — Website Vulnerability Scanner                        ║
║   Author   : Chandransh Ranjan                                               ║
║   Version  : 2.4                                                             ║
║   Standard : OWASP Top 10 (2021)                                             ║
║   License  : For authorized security testing only                            ║
║                                                                              ║
║   Endpoints:                                                                 ║
║     POST /api/scan    → Run full OWASP scan, returns JSON                   ║
║     POST /api/report  → Generate branded WebCure PDF report                 ║
║     GET  /api/health  → Health check                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ── Standard library ──────────────────────────────────────────────────────────
import os
import re
import ssl
import io
import socket
import logging
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Third-party ───────────────────────────────────────────────────────────────
import requests
import dns.resolver
import dns.zone
import dns.query
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_login import LoginManager, login_required

from models import db, User
from auth import auth_bp

load_dotenv()

# ── ReportLab (WebCure PDF engine) ────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak, Flowable
)

# ── WebCure metadata ──────────────────────────────────────────────────────────
WEBCURE_NAME    = "WebCure"
WEBCURE_VERSION = "2.4"
WEBCURE_AUTHOR  = "Chandransh Ranjan"
WEBCURE_STANDARD = "OWASP Top 10 (2021)"
WEBCURE_TAGLINE  = "Website Vulnerability Scanner & Security Audit Engine"

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [{WEBCURE_NAME}] [%(levelname)s] %(message)s"
)
log = logging.getLogger(WEBCURE_NAME)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Session secret — required by flask-login
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")

# Database — Railway injects DATABASE_URL from the linked Postgres service
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///webcure.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# CORS — allow credentials so the session cookie is sent cross-origin
CORS(app, resources={r"/api/*": {"origins": os.environ.get("CORS_ORIGINS", "*")}},
     supports_credentials=True)

# ── Database ──────────────────────────────────────────────────────────────────
db.init_app(app)

# ── Login manager ─────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = "auth.login"

@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": True, "message": "Authentication required."}), 401

# ── Auth blueprint ────────────────────────────────────────────────────────────
app.register_blueprint(auth_bp)

# ── Create tables on first run ────────────────────────────────────────────────
with app.app_context():
    db.create_all()

# ── Scan constants ────────────────────────────────────────────────────────────
REQUEST_TIMEOUT      = 12
MAX_REDIRECTS        = 5
XSS_PAYLOADS         = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    'javascript:alert(1)',
    '<svg onload=alert(1)>',
]
SQLI_PAYLOADS        = ["'", '"', "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"]
OPEN_REDIRECT_PARAMS = ['url','redirect','next','return','goto','destination','redir','target']
SENSITIVE_PATHS      = [
    '/.env','/.git/config','/config.php','/wp-config.php',
    '/admin','/admin/','/administrator','/phpinfo.php',
    '/server-status','/server-info','/.htaccess',
    '/backup.zip','/backup.sql','/dump.sql',
    '/api/swagger.json','/api/openapi.json','/swagger-ui.html',
    '/actuator','/actuator/env','/actuator/health',
    '/.DS_Store','/crossdomain.xml','/clientaccesspolicy.xml',
    '/robots.txt','/sitemap.xml','/web.config',
    '/__debug__/','/django-admin/','/graphql',
]
WEAK_CIPHERS         = ['RC4','DES','MD5','3DES','EXPORT','NULL','ANON']


# ══════════════════════════════════════════════════════════════════════════════
#  DATA CLASS
# ══════════════════════════════════════════════════════════════════════════════

class Finding:
    """A single WebCure security finding aligned to OWASP Top 10 (2021)."""
    def __init__(self, severity, owasp_id, owasp_name, title,
                 description, remediation="", evidence="", cvss=0.0):
        self.severity    = severity       # CRITICAL / HIGH / MEDIUM / LOW / INFO
        self.owasp_id    = owasp_id       # e.g. "A02:2021"
        self.owasp_name  = owasp_name     # e.g. "Cryptographic Failures"
        self.title       = title
        self.description = description
        self.remediation = remediation
        self.evidence    = evidence
        self.cvss        = cvss           # CVSS v3 base score estimate

    def to_dict(self):
        return {
            "severity":    self.severity,
            "owasp_id":    self.owasp_id,
            "owasp_name":  self.owasp_name,
            "name":        self.title,
            "description": self.description,
            "remediation": self.remediation,
            "evidence":    self.evidence,
            "cvss":        self.cvss,
            "tool":        WEBCURE_NAME,
            "author":      WEBCURE_AUTHOR,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def make_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"Mozilla/5.0 ({WEBCURE_NAME} Security Scanner v{WEBCURE_VERSION}; Author: {WEBCURE_AUTHOR})"
    })
    s.max_redirects = MAX_REDIRECTS
    return s

def safe_get(session, url, **kwargs):
    try:
        return session.get(url, timeout=REQUEST_TIMEOUT, verify=True, allow_redirects=True, **kwargs)
    except requests.exceptions.SSLError:
        try:
            return session.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True, **kwargs)
        except Exception:
            return None
    except Exception:
        return None

def safe_post(session, url, data=None, **kwargs):
    try:
        return session.post(url, data=data, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True, **kwargs)
    except Exception:
        return None

def extract_domain(url):
    return urllib.parse.urlparse(url).netloc.split(":")[0]

def is_private_ip(host):
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def validate_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http","https"):
        return False, "URL must start with http:// or https://"
    if not parsed.netloc:
        return False, "Invalid URL: missing host"
    if is_private_ip(parsed.netloc.split(":")[0]):
        return False, f"{WEBCURE_NAME}: Scanning private/internal IPs is not permitted (SSRF protection)"
    return True, ""

def score_from_findings(findings):
    weights = {"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":1}
    return min(100, sum(weights.get(f.severity,0) for f in findings))


# ══════════════════════════════════════════════════════════════════════════════
#  A01 – BROKEN ACCESS CONTROL
# ══════════════════════════════════════════════════════════════════════════════

def check_broken_access_control(session, base_url):
    findings = []
    exposed  = []

    def probe(path):
        r = safe_get(session, base_url.rstrip("/") + path)
        if r and r.status_code == 200 and len(r.content) > 0:
            exposed.append((path, r.text[:120].strip().replace("\n"," ")))

    with ThreadPoolExecutor(max_workers=10) as ex:
        ex.map(probe, SENSITIVE_PATHS)

    for path, snippet in exposed:
        findings.append(Finding("HIGH","A01:2021","Broken Access Control",
            f"Sensitive Resource Exposed: {path}",
            f"The path `{path}` is publicly accessible without authentication.",
            "Restrict access with server-level ACLs or authentication middleware.",
            f"HTTP 200 at {base_url.rstrip('/')}{path} | Preview: {snippet[:80]}",7.5))

    for path in ["/","/images/","/uploads/","/static/","/files/","/backup/"]:
        r = safe_get(session, base_url.rstrip("/") + path)
        if r and r.status_code == 200:
            if any(x in r.text for x in ["Index of /","Directory listing","<title>Index of"]):
                findings.append(Finding("MEDIUM","A01:2021","Broken Access Control",
                    f"Directory Listing Enabled: {path}",
                    "Web server returns directory listings, exposing file structure.",
                    "Disable directory listing in server config (e.g. Options -Indexes in Apache).",
                    f"Directory listing detected at {base_url.rstrip('/')}{path}",5.3))

    for method in ["TRACE","DELETE","PUT","CONNECT"]:
        try:
            r = session.request(method, base_url, timeout=8, verify=False)
            if r and r.status_code not in [405,403,501]:
                findings.append(Finding("MEDIUM","A01:2021","Broken Access Control",
                    f"HTTP Method {method} Allowed",
                    f"The server accepted a {method} request (status {r.status_code}).",
                    "Disable unused HTTP methods in server configuration.",
                    f"{method} {base_url} → HTTP {r.status_code}",5.0))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A02 – CRYPTOGRAPHIC FAILURES
# ══════════════════════════════════════════════════════════════════════════════

def check_cryptographic_failures(session, base_url):
    findings = []
    parsed   = urllib.parse.urlparse(base_url)
    host     = parsed.netloc.split(":")[0]
    port     = int(parsed.port or 443)

    if parsed.scheme == "http":
        findings.append(Finding("HIGH","A02:2021","Cryptographic Failures",
            "Site Served Over Plaintext HTTP",
            "The site does not use HTTPS, transmitting data in cleartext.",
            "Obtain a TLS certificate (e.g. Let's Encrypt) and redirect all HTTP to HTTPS.",
            "URL scheme is http://",7.4))
        return findings

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                             server_hostname=host) as conn:
            cert_bin = conn.getpeercert(binary_form=True)
            cipher   = conn.cipher()
            tls_ver  = conn.version()

        cert    = x509.load_der_x509_certificate(cert_bin, default_backend())
        now     = datetime.now(timezone.utc)
        expires = cert.not_valid_after_utc if hasattr(cert,"not_valid_after_utc") \
                  else cert.not_valid_after.replace(tzinfo=timezone.utc)
        days    = (expires - now).days

        if days < 0:
            findings.append(Finding("CRITICAL","A02:2021","Cryptographic Failures",
                "SSL Certificate Has Expired",
                f"Certificate expired {abs(days)} days ago.",
                "Renew the certificate immediately.",
                f"Expired: {expires.strftime('%Y-%m-%d')}",9.1))
        elif days < 14:
            findings.append(Finding("HIGH","A02:2021","Cryptographic Failures",
                f"SSL Certificate Expiring in {days} Days",
                "Certificate about to expire, risking service disruption.",
                "Renew immediately.",
                f"Expires: {expires.strftime('%Y-%m-%d')}",6.5))
        elif days < 30:
            findings.append(Finding("MEDIUM","A02:2021","Cryptographic Failures",
                f"SSL Certificate Expiring Soon ({days} Days)",
                "Certificate expiry is approaching.",
                "Schedule certificate renewal.",
                f"Expires: {expires.strftime('%Y-%m-%d')}",4.3))

        sig_algo = cert.signature_hash_algorithm
        if sig_algo and sig_algo.name in ("md5","sha1"):
            findings.append(Finding("HIGH","A02:2021","Cryptographic Failures",
                f"Weak Certificate Signature: {sig_algo.name.upper()}",
                f"{sig_algo.name.upper()} is cryptographically broken.",
                "Re-issue certificate with SHA-256 or stronger.",
                f"Algorithm: {sig_algo.name}",7.0))

        if tls_ver in ("TLSv1","TLSv1.1","SSLv2","SSLv3"):
            findings.append(Finding("HIGH","A02:2021","Cryptographic Failures",
                f"Deprecated TLS Version: {tls_ver}",
                f"{tls_ver} has known vulnerabilities (POODLE, BEAST).",
                "Accept only TLS 1.2 and TLS 1.3.",
                f"Negotiated: {tls_ver}",7.5))

        if cipher:
            for wc in WEAK_CIPHERS:
                if wc in (cipher[0] or "").upper():
                    findings.append(Finding("HIGH","A02:2021","Cryptographic Failures",
                        f"Weak Cipher Suite: {cipher[0]}",
                        f"Cipher contains {wc}, which is cryptographically weak.",
                        "Use only AEAD cipher suites (AES-GCM, ChaCha20).",
                        f"Cipher: {cipher[0]} ({cipher[2]} bits)",7.4))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding("HIGH","A02:2021","Cryptographic Failures",
            "SSL Certificate Validation Failed",str(e),
            "Ensure chain is complete and signed by a trusted CA.",str(e)[:200],7.4))
    except Exception as e:
        log.warning(f"SSL check error: {e}")

    if parsed.scheme == "https":
        try:
            r = requests.get("http://" + parsed.netloc + (parsed.path or "/"),
                             timeout=8, allow_redirects=False)
            if r.status_code not in [301,302,307,308]:
                findings.append(Finding("MEDIUM","A02:2021","Cryptographic Failures",
                    "HTTP Does Not Redirect to HTTPS",
                    "Users accessing HTTP are not forced to HTTPS.",
                    "Add a permanent 301 redirect from HTTP to HTTPS.",
                    f"HTTP {r.status_code} (expected 301/302)",5.3))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A03 – INJECTION
# ══════════════════════════════════════════════════════════════════════════════

def check_injection(session, base_url, soup):
    findings = []
    parsed   = urllib.parse.urlparse(base_url)
    params   = urllib.parse.parse_qs(parsed.query)

    if params:
        for param in list(params.keys())[:3]:
            for payload in XSS_PAYLOADS[:3]:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params,doseq=True)).geturl()
                r = safe_get(session, test_url)
                if r and payload in r.text:
                    findings.append(Finding("HIGH","A03:2021","Injection",
                        f"Reflected XSS in Parameter: {param}",
                        f"Parameter `{param}` reflects user input without sanitization.",
                        "Encode all output. Implement a strict Content-Security-Policy.",
                        f"Payload reflected: {payload[:60]}",7.2))
                    break

    if soup:
        for form in soup.find_all("form")[:3]:
            action   = form.get("action", base_url)
            method   = form.get("method","get").lower()
            form_url = urllib.parse.urljoin(base_url, action)
            for payload in XSS_PAYLOADS[:2]:
                data = {}
                for inp in form.find_all("input"):
                    name  = inp.get("name")
                    itype = inp.get("type","text")
                    if name:
                        data[name] = payload if itype in ("text","search","email","url","textarea","hidden") \
                                     else inp.get("value","test")
                if not data: continue
                r = safe_post(session,form_url,data=data) if method=="post" \
                    else safe_get(session,form_url,params=data)
                if r and payload in r.text:
                    findings.append(Finding("HIGH","A03:2021","Injection",
                        "Reflected XSS via Form Input",
                        f"Form at `{form_url}` reflects unsanitized user input.",
                        "Sanitize and encode all user-supplied data before rendering.",
                        f"Payload reflected: {payload[:60]}",7.2))
                    break

    if params:
        sql_errors = ["you have an error in your sql syntax","warning: mysql",
                      "unclosed quotation mark","pg::syntaxerror","sqlite3::exception",
                      "ora-01756","microsoft sql native client","invalid sql statement"]
        for param in list(params.keys())[:2]:
            for payload in SQLI_PAYLOADS[:3]:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params,doseq=True)).geturl()
                r = safe_get(session, test_url)
                if r:
                    for err in sql_errors:
                        if err in r.text.lower():
                            findings.append(Finding("CRITICAL","A03:2021","Injection",
                                f"SQL Injection Error Disclosure: {param}",
                                "Database error messages exposed, indicating SQL injection vulnerability.",
                                "Use parameterized queries. Suppress DB errors in production.",
                                f"DB error keyword found: {err}",9.8))
                            break
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A04 / A05 – SECURITY HEADERS & MISCONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

def check_security_headers(session, base_url):
    findings = []
    r = safe_get(session, base_url)
    if not r: return findings
    headers = {k.lower():v for k,v in r.headers.items()}

    required = {
        "strict-transport-security": ("HIGH","Missing HSTS Header",
            "Without HSTS, browsers may connect over HTTP.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",6.5),
        "content-security-policy": ("HIGH","Missing Content-Security-Policy (CSP)",
            "No CSP exposes the site to XSS and data injection.",
            "Define: Content-Security-Policy: default-src 'self'",6.1),
        "x-content-type-options": ("MEDIUM","Missing X-Content-Type-Options",
            "Browsers may MIME-sniff responses, enabling content injection.",
            "Add: X-Content-Type-Options: nosniff",4.3),
        "x-frame-options": ("MEDIUM","Missing X-Frame-Options",
            "Page can be framed for clickjacking attacks.",
            "Add: X-Frame-Options: DENY",4.3),
        "referrer-policy": ("LOW","Missing Referrer-Policy",
            "Referrer info may leak sensitive URL data.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin",3.1),
        "permissions-policy": ("LOW","Missing Permissions-Policy",
            "Browser features (camera, mic, geolocation) are unrestricted.",
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",3.1),
        "cross-origin-opener-policy": ("LOW","Missing Cross-Origin-Opener-Policy",
            "Pages may be vulnerable to cross-origin attacks.",
            "Add: Cross-Origin-Opener-Policy: same-origin",3.7),
    }

    for hdr, (sev, title, desc, fix, cvss) in required.items():
        if hdr not in headers:
            findings.append(Finding(sev,"A05:2021","Security Misconfiguration",
                title, desc, fix, f"Header `{hdr}` absent.", cvss))

    csp = headers.get("content-security-policy","")
    if csp:
        checks = [
            ("'unsafe-inline'","MEDIUM","CSP Allows 'unsafe-inline' Scripts",
             "'unsafe-inline' negates CSP XSS protection.","Remove 'unsafe-inline'. Use nonces or hashes.",5.4),
            ("'unsafe-eval'","MEDIUM","CSP Allows 'unsafe-eval'",
             "Allows execution of arbitrary strings as code.","Remove 'unsafe-eval'. Refactor code.",5.4),
            ("*","HIGH","CSP Uses Wildcard (*) Source",
             "Wildcard defeats CSP entirely.","Enumerate specific origins.",6.5),
        ]
        for val, sev, title, desc, fix, cvss in checks:
            if val in csp:
                findings.append(Finding(sev,"A05:2021","Security Misconfiguration",
                    title, desc, fix, f"CSP: {csp[:200]}",cvss))

    leaky = {
        "server":             "Server header reveals software identity",
        "x-powered-by":       "Backend technology stack exposed",
        "x-aspnet-version":   "ASP.NET version disclosed",
        "x-aspnetmvc-version":"ASP.NET MVC version disclosed",
        "x-generator":        "CMS/framework generator disclosed",
    }
    for h, reason in leaky.items():
        if h in headers:
            findings.append(Finding("LOW","A05:2021","Security Misconfiguration",
                f"Information Disclosure via {h.title()} Header",
                reason, f"Remove or obfuscate the `{h}` header.",
                f"{h}: {headers[h]}",3.1))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A05 (cont.) – CORS
# ══════════════════════════════════════════════════════════════════════════════

def check_cors(session, base_url):
    findings = []
    evil = "https://evil.webcure-test.io"
    try:
        r    = session.get(base_url, timeout=8, verify=False, headers={"Origin": evil})
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        if acao == "*":
            findings.append(Finding("MEDIUM","A05:2021","Security Misconfiguration",
                "CORS Wildcard Origin Allowed","Any origin can make cross-origin requests.",
                "Specify explicit allowed origins instead of *.",
                "Access-Control-Allow-Origin: *",5.3))
        elif acao == evil:
            sev = "CRITICAL" if acac.lower()=="true" else "HIGH"
            findings.append(Finding(sev,"A05:2021","Security Misconfiguration",
                "CORS Reflects Arbitrary Origin" + (" + Credentials" if sev=="CRITICAL" else ""),
                "Server echoes caller's Origin without validation." +
                (" Combined with credentials, this allows authenticated cross-origin attacks." if sev=="CRITICAL" else ""),
                "Validate Origin against an explicit allowlist.",
                f"ACAO: {acao} | ACAC: {acac}",9.0 if sev=="CRITICAL" else 7.1))
    except Exception:
        pass
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A06 – VULNERABLE & OUTDATED COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════

def check_vulnerable_components(session, base_url, soup, response_headers):
    findings = []
    headers  = {k.lower():v for k,v in response_headers.items()}
    patterns = [
        (r"apache[/ ](\d+\.\d+\.?\d*)",       "Apache HTTP Server","2.4.52"),
        (r"nginx[/ ](\d+\.\d+\.?\d*)",         "nginx","1.24.0"),
        (r"php[/ ](\d+\.\d+\.?\d*)",           "PHP","8.1.0"),
        (r"openssl[/ ](\d+\.\d+\.?\d*\w*)",    "OpenSSL","3.0.0"),
        (r"tomcat[/ ](\d+\.\d+\.?\d*)",        "Apache Tomcat","10.1.0"),
        (r"wordpress[/ ](\d+\.\d+\.?\d*)",     "WordPress","6.3"),
        (r"drupal[/ ](\d+\.\d+\.?\d*)",        "Drupal","10.0"),
        (r"jquery[/ v]+(\d+\.\d+\.?\d*)",      "jQuery","3.7.0"),
        (r"bootstrap[/ ](\d+\.\d+\.?\d*)",     "Bootstrap","5.3.0"),
    ]
    combined = " ".join(headers.values())
    if soup: combined += " " + soup.get_text()[:5000]

    for pattern, product, min_ver in patterns:
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            findings.append(Finding("MEDIUM","A06:2021","Vulnerable and Outdated Components",
                f"{product} Version Fingerprinted: {m.group(1)}",
                f"{product} {m.group(1)} is exposed. Verify it is not end-of-life (recommended >= {min_ver}).",
                f"Update {product} to the latest stable release and remove version disclosure.",
                f"Detected version: {m.group(1)}",5.5))

    if soup:
        for script in soup.find_all("script", src=True):
            src = script.get("src","")
            if any(cdn in src for cdn in ["cdn.","cdnjs.","unpkg.","jsdelivr.","ajax.googleapis"]):
                if not script.get("integrity"):
                    findings.append(Finding("MEDIUM","A08:2021","Software and Data Integrity Failures",
                        "External Script Without Subresource Integrity (SRI)",
                        f"Script `{src[:100]}` from CDN has no integrity hash.",
                        "Add `integrity` and `crossorigin` attributes to all external scripts.",
                        f"src={src[:120]}",6.1))
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A07 – IDENTIFICATION & AUTHENTICATION FAILURES
# ══════════════════════════════════════════════════════════════════════════════

def check_auth_failures(session, base_url, soup, response):
    findings = []
    if response:
        raw_cookies = [v for k,v in response.headers.items() if k.lower()=="set-cookie"]
        for cookie in raw_cookies:
            cl   = cookie.lower()
            name = cookie.split("=")[0].strip()
            if "httponly" not in cl:
                findings.append(Finding("MEDIUM","A07:2021","Identification and Authentication Failures",
                    f"Cookie Missing HttpOnly: {name}",
                    "Cookies without HttpOnly can be read by JavaScript (XSS session theft).",
                    "Add HttpOnly to all session cookies.",
                    f"Set-Cookie: {cookie[:120]}",5.4))
            if "secure" not in cl:
                findings.append(Finding("MEDIUM","A07:2021","Identification and Authentication Failures",
                    f"Cookie Missing Secure Flag: {name}",
                    "Cookie may transmit over plain HTTP.",
                    "Add Secure attribute to all cookies.",
                    f"Set-Cookie: {cookie[:120]}",5.4))
            if "samesite" not in cl:
                findings.append(Finding("LOW","A07:2021","Identification and Authentication Failures",
                    f"Cookie Missing SameSite: {name}",
                    "Missing SameSite leaves cookies vulnerable to CSRF.",
                    "Set SameSite=Strict or SameSite=Lax.",
                    f"Set-Cookie: {cookie[:120]}",4.3))

    if soup:
        for form in soup.find_all("form"):
            inputs = [i.get("type","").lower() for i in form.find_all("input")]
            if "password" not in inputs: continue
            hidden     = form.find_all("input", type="hidden")
            csrf_names = [i.get("name","").lower() for i in hidden]
            has_csrf   = any(k in " ".join(csrf_names)
                             for k in ["csrf","token","_token","authenticity","nonce","xsrf"])
            if not has_csrf:
                findings.append(Finding("HIGH","A07:2021","Identification and Authentication Failures",
                    "Login Form Missing CSRF Token",
                    "No anti-CSRF token in login form. Vulnerable to Cross-Site Request Forgery.",
                    "Include a unique, unpredictable CSRF token in all state-changing forms.",
                    f"Form action: {form.get('action','unknown')}",6.5))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A09 – SECURITY LOGGING & MONITORING
# ══════════════════════════════════════════════════════════════════════════════

def check_logging_monitoring(session, base_url):
    findings = []
    probes   = [
        base_url.rstrip("/") + "/this-does-not-exist-webcure",
        base_url.rstrip("/") + "/?id=1'",
    ]
    patterns = [
        (r"stack trace",            "Stack trace exposed"),
        (r"traceback \(most recent call","Python traceback exposed"),
        (r"fatal error.*on line \d+","PHP fatal error exposed"),
        (r"mysql_fetch",            "MySQL function name exposed"),
        (r"activerecord::",         "Ruby on Rails ActiveRecord error"),
        (r"system\.web\.httpexception",".NET exception exposed"),
    ]
    for url in probes:
        r = safe_get(session, url)
        if r and r.status_code not in [404,410]:
            body = r.text.lower()
            for pattern, label in patterns:
                if re.search(pattern, body):
                    findings.append(Finding("MEDIUM","A09:2021","Security Logging and Monitoring Failures",
                        f"Verbose Error Disclosure: {label}",
                        "Detailed error messages reveal implementation details useful to attackers.",
                        "Display generic error pages in production. Log details server-side only.",
                        f"Pattern matched at {url}",5.3))
                    break
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  A10 – SSRF / OPEN REDIRECT
# ══════════════════════════════════════════════════════════════════════════════

def check_ssrf_open_redirect(session, base_url):
    findings = []
    parsed   = urllib.parse.urlparse(base_url)
    payload  = "https://evil.webcure-test.io"
    for param in OPEN_REDIRECT_PARAMS:
        test_url = parsed._replace(query=urllib.parse.urlencode({param: payload})).geturl()
        try:
            r = session.get(test_url, timeout=8, verify=False, allow_redirects=False)
            if r and r.status_code in (301,302,307,308):
                loc = r.headers.get("Location","")
                if "evil.webcure-test.io" in loc:
                    findings.append(Finding("HIGH","A10:2021","Server-Side Request Forgery",
                        f"Open Redirect via Parameter: {param}",
                        f"Parameter `{param}` can redirect users to arbitrary external URLs.",
                        "Validate redirect targets against an allowlist. Reject external URLs.",
                        f"Location: {loc[:150]}",6.1))
        except Exception:
            pass
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  DNS & PORT CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def check_dns(base_url):
    findings = []
    domain   = extract_domain(base_url)
    try:
        answers   = dns.resolver.resolve(domain, "TXT")
        spf_found = any("v=spf1" in str(r).lower() for r in answers)
        if not spf_found:
            findings.append(Finding("MEDIUM","A05:2021","Security Misconfiguration",
                "Missing SPF DNS Record","Without SPF, attackers can spoof email from this domain.",
                "Add TXT record: v=spf1 include:... -all",f"No SPF on {domain}",5.3))
        dmarc = False
        try:
            da    = dns.resolver.resolve(f"_dmarc.{domain}","TXT")
            dmarc = any("v=dmarc1" in str(r).lower() for r in da)
        except Exception:
            pass
        if not dmarc:
            findings.append(Finding("MEDIUM","A05:2021","Security Misconfiguration",
                "Missing DMARC DNS Record","Without DMARC, domain can be used in phishing.",
                "Add _dmarc TXT: v=DMARC1; p=reject; rua=mailto:...",f"No DMARC on {domain}",5.3))
    except Exception:
        pass

    try:
        ns_records = dns.resolver.resolve(domain,"NS")
        for ns in ns_records:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns.target), domain, timeout=5))
                if zone:
                    findings.append(Finding("CRITICAL","A05:2021","Security Misconfiguration",
                        f"DNS Zone Transfer Allowed: {ns.target}",
                        "Nameserver allows unauthenticated zone transfers, exposing full DNS infrastructure.",
                        "Restrict AXFR to authorised secondary nameservers only.",
                        f"Zone transfer succeeded from {ns.target}",9.1))
            except Exception:
                pass
    except Exception:
        pass

    try:
        dns.resolver.resolve(domain,"CAA")
    except dns.resolver.NoAnswer:
        findings.append(Finding("LOW","A02:2021","Cryptographic Failures",
            "Missing CAA DNS Record","Without CAA, any CA can issue certificates for this domain.",
            "Add CAA records to restrict certificate issuance.",f"No CAA on {domain}",3.7))
    except Exception:
        pass

    return findings


def check_open_ports(base_url):
    findings = []
    host     = extract_domain(base_url)
    risky    = {
        21:    ("FTP","MEDIUM"),
        22:    ("SSH","INFO"),
        23:    ("Telnet (unencrypted)","HIGH"),
        3306:  ("MySQL","HIGH"),
        3389:  ("RDP","HIGH"),
        5432:  ("PostgreSQL","HIGH"),
        6379:  ("Redis (often unauthenticated)","CRITICAL"),
        27017: ("MongoDB (often unauthenticated)","CRITICAL"),
        8080:  ("HTTP-alternate","MEDIUM"),
    }
    def probe(port):
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close(); return port
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(probe, p): p for p in risky}
        for fut in as_completed(futures):
            port = fut.result()
            if port and port in risky:
                service, severity = risky[port]
                if severity in ("CRITICAL","HIGH","MEDIUM"):
                    findings.append(Finding(severity,"A05:2021","Security Misconfiguration",
                        f"Sensitive Port Open: {port}/{service}",
                        f"Port {port} ({service}) is reachable from the internet.",
                        f"Firewall port {port} and restrict to trusted IPs only.",
                        f"TCP connect to {host}:{port} succeeded.",
                        8.0 if severity=="CRITICAL" else 6.5 if severity=="HIGH" else 4.3))
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MASTER SCAN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def run_full_scan(url, options):
    log.info(f"Starting {WEBCURE_NAME} scan: {url}")
    session       = make_session()
    base_response = safe_get(session, url)
    soup          = None
    if base_response:
        try: soup = BeautifulSoup(base_response.text, "html.parser")
        except Exception: pass

    tasks = {
        "access_control": lambda: check_broken_access_control(session, url),
        "crypto":         lambda: check_cryptographic_failures(session, url),
        "injection":      lambda: check_injection(session, url, soup),
        "headers":        lambda: check_security_headers(session, url),
        "cors":           lambda: check_cors(session, url),
        "components":     lambda: check_vulnerable_components(session, url, soup,
                                      base_response.headers if base_response else {}),
        "auth":           lambda: check_auth_failures(session, url, soup, base_response),
        "logging":        lambda: check_logging_monitoring(session, url),
        "ssrf":           lambda: check_ssrf_open_redirect(session, url),
        "dns":            lambda: check_dns(url),
        "ports":          lambda: check_open_ports(url),
    }

    all_findings = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        future_map = {ex.submit(fn): name for name, fn in tasks.items()}
        for fut in as_completed(future_map):
            try:
                results = fut.result()
                all_findings.extend(results)
                log.info(f"[{future_map[fut]}] {len(results)} findings")
            except Exception as e:
                log.error(f"[{future_map[fut]}] crashed: {e}")

    seen, unique = set(), []
    for f in all_findings:
        if f.title not in seen:
            seen.add(f.title); unique.append(f)

    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    unique.sort(key=lambda f: order.get(f.severity,5))

    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in unique: counts[f.severity] = counts.get(f.severity,0)+1

    return {
        "url":             url,
        "scanned_at":      datetime.now(timezone.utc).isoformat(),
        "risk_score":      score_from_findings(unique),
        "total_findings":  len(unique),
        "counts":          counts,
        "vulnerabilities": [f.to_dict() for f in unique],
        "owasp_version":   WEBCURE_STANDARD,
        "tool":            WEBCURE_NAME,
        "tool_version":    WEBCURE_VERSION,
        "author":          WEBCURE_AUTHOR,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  WEBCURE PDF REPORT GENERATOR  —  Professional Corporate Edition
# ══════════════════════════════════════════════════════════════════════════════

# ── Professional colour palette (light, corporate) ───────────────────────────
C_BG        = colors.white
C_SURFACE   = colors.HexColor("#F7F9FC")
C_SURFACE2  = colors.HexColor("#EEF2F7")
C_NAVY      = colors.HexColor("#0D2240")
C_NAVY2     = colors.HexColor("#163560")
C_ACCENT    = colors.HexColor("#1A6FBF")
C_ACCENT2   = colors.HexColor("#2E86C1")
C_TEXT      = colors.HexColor("#1A2B3C")
C_MUTED     = colors.HexColor("#6B7C93")
C_BORDER    = colors.HexColor("#D0DAE6")
C_WHITE     = colors.white
C_WARN      = colors.HexColor("#E67E22")
C_DANGER    = colors.HexColor("#C0392B")

SEV_COLORS = {
    "CRITICAL": (colors.HexColor("#C0392B"), colors.HexColor("#FDEDEC")),
    "HIGH":     (colors.HexColor("#E74C3C"), colors.HexColor("#FDECEA")),
    "MEDIUM":   (colors.HexColor("#E67E22"), colors.HexColor("#FEF5E7")),
    "LOW":      (colors.HexColor("#F39C12"), colors.HexColor("#FEF9E7")),
    "INFO":     (colors.HexColor("#2E86C1"), colors.HexColor("#EBF5FB")),
}


class ColorRect(Flowable):
    """Solid colour rectangle — section rules and accent bars."""
    def __init__(self, width, height, color, radius=0):
        super().__init__()
        self.width  = width
        self.height = height
        self.color  = color
        self.radius = radius

    def draw(self):
        self.canv.setFillColor(self.color)
        if self.radius:
            self.canv.roundRect(0, 0, self.width, self.height, self.radius, fill=1, stroke=0)
        else:
            self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


class SeverityBadge(Flowable):
    """Pill-shaped severity badge for finding cards."""
    def __init__(self, severity, width=70, height=16):
        super().__init__()
        self.severity = severity
        self.width    = width
        self.height   = height

    def draw(self):
        fg, bg = SEV_COLORS.get(self.severity, (C_ACCENT, C_SURFACE))
        self.canv.setFillColor(bg)
        self.canv.roundRect(0, 0, self.width, self.height, self.height/2, fill=1, stroke=0)
        self.canv.setStrokeColor(fg)
        self.canv.setLineWidth(0.8)
        self.canv.roundRect(0, 0, self.width, self.height, self.height/2, fill=0, stroke=1)
        self.canv.setFillColor(fg)
        self.canv.setFont("Helvetica-Bold", 7)
        self.canv.drawCentredString(self.width/2, 4, self.severity)


def build_pdf_report(data: dict) -> bytes:
    """Generate a professional corporate WebCure PDF security report."""
    import html as _html
    buf    = io.BytesIO()
    W, H   = A4
    MARGIN = 22 * mm

    def on_first_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_WHITE)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Navy header band — top 38% of page
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, H * 0.62, W, H * 0.38, fill=1, stroke=0)
        # Accent rule below navy band
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, H * 0.62 - 4, W, 4, fill=1, stroke=0)
        # Left accent bar
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, 0, 5, H, fill=1, stroke=0)
        # Subtle WC watermark in navy zone
        canvas.setFillColor(colors.HexColor("#1A3A60"))
        canvas.setFont("Helvetica-Bold", 80)
        canvas.drawRightString(W - 20, H * 0.68, "WC")
        canvas.restoreState()

    def on_later_pages(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_WHITE)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Left accent bar
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, 0, 4, H, fill=1, stroke=0)
        # Top header bar
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, H - 26, W, 26, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#A0B4C8"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(MARGIN + 8, H - 16,
            f"{WEBCURE_NAME}  |  Confidential Security Assessment  |  {WEBCURE_STANDARD}")
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.drawRightString(W - MARGIN, H - 16, f"Page {doc.page}")
        # Footer
        canvas.setFillColor(colors.HexColor("#EEF2F7"))
        canvas.rect(0, 0, W, 20, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#6B7C93"))
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(MARGIN + 8, 6,
            f"{WEBCURE_NAME} v{WEBCURE_VERSION}  |  Author: {WEBCURE_AUTHOR}  |  Scan: {data.get('scanned_at','')[:10]}")
        canvas.drawRightString(W - MARGIN, 6, "FOR AUTHORIZED USE ONLY — CONFIDENTIAL")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN + 4, rightMargin=MARGIN,
        topMargin=MARGIN + 14, bottomMargin=MARGIN + 4,
    )

    def ps(name, font="Helvetica", size=10, color=None, align=TA_LEFT,
           bold=False, leading=None, sb=0, sa=0):
        if color is None:
            color = C_TEXT
        return ParagraphStyle(name,
            fontName="Helvetica-Bold" if bold else font,
            fontSize=size, textColor=color, alignment=align,
            leading=leading or size * 1.45,
            spaceBefore=sb, spaceAfter=sa)

    story = []

    # ── COVER PAGE ─────────────────────────────────────────────────────────────
    target_url = data.get("url", "Unknown")
    scan_date  = data.get("scanned_at", "")[:10]
    score      = data.get("risk_score", 0)
    vuln_ct    = data.get("total_findings", 0)
    counts     = data.get("counts", {})
    risk_level = "CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=35 else "LOW"

    story.append(Spacer(1, H * 0.40))
    story.append(Paragraph(
        "WEBSITE VULNERABILITY ASSESSMENT REPORT",
        ps("cv_tag", size=8, color=C_MUTED, bold=True, sa=2)))
    story.append(ColorRect(W - 2*MARGIN - 4, 1.5, C_BORDER))
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph(WEBCURE_NAME,
        ps("cv_title", size=42, color=C_NAVY, bold=True, leading=46)))
    story.append(Paragraph(WEBCURE_TAGLINE,
        ps("cv_sub", size=12, color=C_ACCENT, sa=6)))
    story.append(Spacer(1, 8*mm))

    risk_fg, risk_bg = SEV_COLORS.get(risk_level, (C_ACCENT, C_SURFACE))
    meta_rows = [
        [Paragraph("Target",         ps("ml1",size=8,color=C_MUTED,bold=True)),
         Paragraph(_html.escape(target_url), ps("mv1",size=8,color=C_TEXT))],
        [Paragraph("Scan Date",      ps("ml2",size=8,color=C_MUTED,bold=True)),
         Paragraph(scan_date,        ps("mv2",size=8,color=C_TEXT))],
        [Paragraph("Risk Score",     ps("ml3",size=8,color=C_MUTED,bold=True)),
         Paragraph(f"<b>{score} / 100 — {risk_level}</b>", ps("mv3",size=8,color=risk_fg,bold=True))],
        [Paragraph("Total Findings", ps("ml4",size=8,color=C_MUTED,bold=True)),
         Paragraph(str(vuln_ct),     ps("mv4",size=8,color=C_TEXT))],
        [Paragraph("Standard",       ps("ml5",size=8,color=C_MUTED,bold=True)),
         Paragraph(WEBCURE_STANDARD, ps("mv5",size=8,color=C_TEXT))],
        [Paragraph("Prepared By",    ps("ml6",size=8,color=C_MUTED,bold=True)),
         Paragraph(f"{WEBCURE_NAME} v{WEBCURE_VERSION}  |  {WEBCURE_AUTHOR}", ps("mv6",size=8,color=C_TEXT))],
        [Paragraph("Classification", ps("ml7",size=8,color=C_MUTED,bold=True)),
         Paragraph("<b>CONFIDENTIAL — Authorized Recipients Only</b>", ps("mv7",size=8,color=C_DANGER,bold=True))],
    ]
    cw_meta = [(W-2*MARGIN-4)*0.28, (W-2*MARGIN-4)*0.72]
    meta_tbl = Table(meta_rows, colWidths=cw_meta)
    meta_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0,0),(-1,-1), [C_SURFACE, C_WHITE]),
        ("LINEBELOW",      (0,0),(-1,-1), 0.5, C_BORDER),
        ("LEFTPADDING",    (0,0),(-1,-1), 8),
        ("RIGHTPADDING",   (0,0),(-1,-1), 8),
        ("TOPPADDING",     (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 6),
        ("VALIGN",         (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(PageBreak())

    def section_heading(label, number=""):
        prefix = f"{number}.  " if number else ""
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            f"{prefix}{label.upper()}",
            ps(f"sh_{label}", size=10, color=C_NAVY, bold=True, sb=4, sa=2)))
        story.append(ColorRect(W - 2*MARGIN - 4, 2, C_ACCENT))
        story.append(Spacer(1, 4*mm))

    # ── 1. EXECUTIVE SUMMARY ───────────────────────────────────────────────────
    section_heading("Executive Summary", "1")
    story.append(Paragraph(
        f"This report documents the results of an automated web application security assessment "
        f"performed by <b>{WEBCURE_NAME}</b> against <b>{_html.escape(target_url)}</b> on <b>{scan_date}</b>. "
        f"The assessment was conducted in accordance with the <b>{WEBCURE_STANDARD}</b> framework. "
        f"A total of <b>{vuln_ct} security findings</b> were identified, yielding an aggregate risk "
        f"score of <b>{score} out of 100</b>, classified as <b>{risk_level} RISK</b>. "
        f"Findings classified as Critical or High severity require immediate remediation.",
        ps("exec_body", size=9, color=C_TEXT, leading=15, sa=6)))
    story.append(Spacer(1, 4*mm))

    risk_box = Table([[
        Paragraph("<b>Overall Risk Score</b>", ps("rb_lbl", size=8, color=C_MUTED)),
        Paragraph(f"<b>{score} / 100</b>", ps("rb_score", size=22, color=risk_fg, bold=True, align=TA_CENTER)),
        Paragraph(f"<b>{risk_level} RISK</b>", ps("rb_level", size=13, color=risk_fg, bold=True, align=TA_CENTER)),
    ]], colWidths=[(W-2*MARGIN-4)*x for x in [0.40, 0.30, 0.30]])
    risk_box.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), risk_bg),
        ("LINEABOVE",     (0,0),(-1,0),  3, risk_fg),
        ("LEFTPADDING",   (0,0),(-1,-1), 12),
        ("RIGHTPADDING",  (0,0),(-1,-1), 12),
        ("TOPPADDING",    (0,0),(-1,-1), 10),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(risk_box)
    story.append(Spacer(1, 6*mm))

    actions = {
        "CRITICAL": "Immediate — fix before deployment",
        "HIGH":     "Urgent — remediate within 7 days",
        "MEDIUM":   "Important — remediate within 30 days",
        "LOW":      "Planned — address in next release cycle",
        "INFO":     "Advisory — review and document",
    }
    sum_rows = [[
        Paragraph("Severity",        ps("suh1",size=8,color=C_WHITE,bold=True)),
        Paragraph("Count",           ps("suh2",size=8,color=C_WHITE,bold=True,align=TA_CENTER)),
        Paragraph("Risk Level",      ps("suh3",size=8,color=C_WHITE,bold=True)),
        Paragraph("Action Required", ps("suh4",size=8,color=C_WHITE,bold=True)),
    ]] + [
        [Paragraph(sev, ps(f"sv_{sev}",size=8,color=SEV_COLORS[sev][0],bold=True)),
         Paragraph(str(counts.get(sev,0)), ps(f"sc_{sev}",size=9,color=C_TEXT,align=TA_CENTER,bold=counts.get(sev,0)>0)),
         Paragraph(sev, ps(f"sl_{sev}",size=8,color=SEV_COLORS[sev][0])),
         Paragraph(actions[sev], ps(f"sa_{sev}",size=8,color=C_TEXT))]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    ]
    sum_tbl = Table(sum_rows, colWidths=[(W-2*MARGIN-4)*x for x in [0.18,0.10,0.18,0.54]])
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0),  C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_SURFACE, C_WHITE]),
        ("GRID",          (0,0),(-1,-1), 0.4, C_BORDER),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("RIGHTPADDING",  (0,0),(-1,-1), 8),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(sum_tbl)
    story.append(PageBreak())

    # ── 2. SCOPE & METHODOLOGY ─────────────────────────────────────────────────
    section_heading("Scope & Methodology", "2")
    story.append(Paragraph("<b>Assessment Scope</b>",
        ps("scope_hdr", size=9, color=C_NAVY, bold=True, sa=2)))
    story.append(Paragraph(
        f"The assessment was limited to the externally accessible web application hosted at "
        f"<b>{_html.escape(target_url)}</b>. No internal network access, source code review, "
        f"or social engineering was performed. Testing was non-destructive and did not intentionally "
        f"disrupt service availability.",
        ps("scope_body", size=9, color=C_TEXT, leading=14, sa=6)))
    story.append(Paragraph("<b>Methodology</b>",
        ps("meth_hdr", size=9, color=C_NAVY, bold=True, sa=2)))
    story.append(Paragraph(
        f"The {WEBCURE_NAME} scanner performs automated checks mapped to the {WEBCURE_STANDARD} "
        f"taxonomy. The following techniques were employed:",
        ps("meth_intro", size=9, color=C_TEXT, leading=14, sa=4)))
    methods = [
        ("Passive Reconnaissance",  "HTTP header analysis, SSL/TLS certificate inspection, DNS enumeration, technology fingerprinting."),
        ("Active Scanning",         "Injection payload testing (SQLi, XSS, SSRF), open redirect probing, sensitive path discovery."),
        ("Configuration Review",    "Security header validation, CORS policy analysis, cookie attribute inspection, HTTP method auditing."),
        ("Component Analysis",      "Third-party library version detection, CDN subresource integrity checks, outdated software identification."),
        ("Network Exposure",        "Common port scanning for exposed services (databases, RDP, FTP, etc.)."),
    ]
    meth_rows = [[Paragraph(t, ps(f"mt{i}",size=8,color=C_NAVY,bold=True)),
                  Paragraph(d, ps(f"md{i}",size=8,color=C_TEXT,leading=12))]
                 for i,(t,d) in enumerate(methods)]
    meth_tbl = Table(meth_rows, colWidths=[(W-2*MARGIN-4)*x for x in [0.28, 0.72]])
    meth_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_SURFACE, C_WHITE]),
        ("LINEBELOW",     (0,0),(-1,-1), 0.4, C_BORDER),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("RIGHTPADDING",  (0,0),(-1,-1), 8),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
    ]))
    story.append(meth_tbl)
    story.append(PageBreak())

    # ── 3. DETAILED FINDINGS ───────────────────────────────────────────────────
    section_heading("Detailed Findings", "3")
    story.append(Paragraph(
        f"The following {vuln_ct} findings are listed in descending order of severity. "
        f"Each finding includes a description, supporting evidence, CVSS v3 score estimate, "
        f"OWASP classification, and recommended remediation guidance.",
        ps("find_intro", size=9, color=C_TEXT, leading=14, sa=6)))

    cw2 = [(W-2*MARGIN-4)*x for x in [0.55, 0.22, 0.23]]

    for i, v in enumerate(data.get("vulnerabilities", []), 1):
        sev         = v.get("severity","INFO").upper()
        fg, bg      = SEV_COLORS.get(sev,(C_ACCENT, C_SURFACE))
        cvss        = v.get("cvss", 0)
        name        = _html.escape(str(v.get("name","") or ""))
        owasp_id    = _html.escape(str(v.get("owasp_id","") or ""))
        owasp_name  = _html.escape(str(v.get("owasp_name","") or ""))
        description = _html.escape(str(v.get("description","") or ""))
        evidence    = _html.escape(str(v.get("evidence","") or "")[:220])
        remediation = _html.escape(str(v.get("remediation","") or ""))

        rows = [
            [Paragraph(f"<b>Finding {i:02d} — {name}</b>",
                        ps(f"fn{i}", size=9, color=C_WHITE, bold=True)),
             Paragraph(f"<b>{sev}</b>",
                        ps(f"fs{i}", size=8, color=fg, bold=True, align=TA_CENTER)),
             Paragraph(f"CVSS <b>{cvss:.1f}</b>" if cvss else "CVSS —",
                        ps(f"fc{i}", size=8, color=C_MUTED, align=TA_CENTER))],
            [Paragraph(f"{owasp_id}  ·  {owasp_name}",
                        ps(f"fo{i}", size=7.5, color=colors.HexColor("#A0B4C8"))), "", ""],
            [Paragraph("<b>Description</b>",
                        ps(f"fdhdr{i}", size=8, color=C_MUTED, bold=True, sa=1)), "", ""],
            [Paragraph(description,
                        ps(f"fd{i}", size=8.5, color=C_TEXT, leading=13)), "", ""],
        ]
        spans = [
            ("SPAN", (0,1), (-1,1)),
            ("SPAN", (0,2), (-1,2)),
            ("SPAN", (0,3), (-1,3)),
        ]
        row_idx = 4

        if evidence:
            rows.append([Paragraph("<b>Evidence</b>",
                         ps(f"fehdr{i}", size=8, color=C_MUTED, bold=True)), "", ""])
            rows.append([Paragraph(evidence,
                         ps(f"fe{i}", font="Courier", size=7.5,
                            color=colors.HexColor("#2C3E50"), leading=11)), "", ""])
            spans += [("SPAN",(0,row_idx),(-1,row_idx)),("SPAN",(0,row_idx+1),(-1,row_idx+1))]
            row_idx += 2

        if remediation:
            rows.append([Paragraph("<b>Recommendation</b>",
                         ps(f"frhdr{i}", size=8, color=C_MUTED, bold=True)), "", ""])
            rows.append([Paragraph(remediation,
                         ps(f"fr{i}", size=8.5, color=colors.HexColor("#1A5276"), leading=13)), "", ""])
            spans += [("SPAN",(0,row_idx),(-1,row_idx)),("SPAN",(0,row_idx+1),(-1,row_idx+1))]

        card = Table(rows, colWidths=cw2)
        card.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),  (-1,0),  C_NAVY),
            ("BACKGROUND",    (0,1),  (-1,1),  C_NAVY2),
            ("BACKGROUND",    (0,2),  (-1,-1), bg),
            ("LINEABOVE",     (0,0),  (-1,0),  3, fg),
            ("LINEBELOW",     (0,-1), (-1,-1), 0.5, C_BORDER),
            ("BOX",           (0,0),  (-1,-1), 0.5, C_BORDER),
            ("LEFTPADDING",   (0,0),  (-1,-1), 10),
            ("RIGHTPADDING",  (0,0),  (-1,-1), 10),
            ("TOPPADDING",    (0,0),  (-1,1),  7),
            ("BOTTOMPADDING", (0,0),  (-1,1),  7),
            ("TOPPADDING",    (0,2),  (-1,-1), 5),
            ("BOTTOMPADDING", (0,2),  (-1,-1), 5),
            ("VALIGN",        (0,0),  (-1,-1), "TOP"),
        ] + spans))
        story.append(KeepTogether([card, Spacer(1, 5*mm)]))

    # ── 4. OWASP TOP 10 REFERENCE ─────────────────────────────────────────────
    story.append(PageBreak())
    section_heading("OWASP Top 10 Reference", "4")

    owasp_ref = [
        ("A01:2021","Broken Access Control","Restrictions on authenticated users not properly enforced."),
        ("A02:2021","Cryptographic Failures","Failures related to cryptography exposing sensitive data."),
        ("A03:2021","Injection","User-supplied data not validated, filtered, or sanitized."),
        ("A04:2021","Insecure Design","Missing or ineffective control design."),
        ("A05:2021","Security Misconfiguration","Missing or incorrect security hardening."),
        ("A06:2021","Vulnerable & Outdated Components","Components with known vulnerabilities in use."),
        ("A07:2021","Identification & Auth Failures","Weaknesses in authentication and session management."),
        ("A08:2021","Software & Data Integrity Failures","Code and infrastructure lacking integrity verification."),
        ("A09:2021","Security Logging & Monitoring Failures","Insufficient logging and monitoring capabilities."),
        ("A10:2021","Server-Side Request Forgery","Server fetching remote resources from user-supplied URLs."),
    ]
    owasp_counts = {}
    for vv in data.get("vulnerabilities",[]):
        oid = vv.get("owasp_id","")
        owasp_counts[oid] = owasp_counts.get(oid,0) + 1

    ref_rows = [[
        Paragraph("ID",          ps("rh1",size=8,color=C_WHITE,bold=True)),
        Paragraph("Category",    ps("rh2",size=8,color=C_WHITE,bold=True)),
        Paragraph("Description", ps("rh3",size=8,color=C_WHITE,bold=True)),
        Paragraph("Findings",    ps("rh4",size=8,color=C_WHITE,bold=True,align=TA_CENTER)),
    ]] + [
        [Paragraph(oid,   ps(f"ri{oid}",font="Courier",size=7,color=C_ACCENT)),
         Paragraph(f"<b>{name}</b>", ps(f"rn{oid}",size=8,color=C_TEXT)),
         Paragraph(desc,  ps(f"rd{oid}",size=7,color=C_MUTED,leading=10)),
         Paragraph(str(owasp_counts[oid]) if oid in owasp_counts else "—",
                   ps(f"rc{oid}",size=9,color=C_DANGER if oid in owasp_counts else C_MUTED,
                      bold=oid in owasp_counts,align=TA_CENTER))]
        for oid, name, desc in owasp_ref
    ]
    ref_tbl = Table(ref_rows, colWidths=[(W-2*MARGIN-4)*x for x in [0.14,0.26,0.44,0.16]], repeatRows=1)
    ref_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0),   C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),  [C_SURFACE, C_WHITE]),
        ("GRID",          (0,0),(-1,-1),  0.4, C_BORDER),
        ("LEFTPADDING",   (0,0),(-1,-1),  6),
        ("RIGHTPADDING",  (0,0),(-1,-1),  6),
        ("TOPPADDING",    (0,0),(-1,-1),  5),
        ("BOTTOMPADDING", (0,0),(-1,-1),  5),
        ("VALIGN",        (0,0),(-1,-1),  "TOP"),
    ]))
    story.append(ref_tbl)
    story.append(Spacer(1, 8*mm))

    # ── 5. DISCLAIMER ──────────────────────────────────────────────────────────
    story.append(ColorRect(W-2*MARGIN-4, 1, C_BORDER))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Disclaimer",
        ps("disc_hdr", size=9, color=C_MUTED, bold=True, sa=3)))
    story.append(Paragraph(
        f"This report was generated automatically by {WEBCURE_NAME} and is intended solely for the "
        f"authorized owner of the scanned target. The findings represent a point-in-time passive "
        f"assessment and may not capture all vulnerabilities. Always consult a qualified security "
        f"professional before making decisions based on this report. Unauthorized use of {WEBCURE_NAME} "
        f"against systems you do not own or have explicit written permission to test is illegal.",
        ps("disc_body", size=8, color=C_MUTED, leading=12)))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"{WEBCURE_NAME} v{WEBCURE_VERSION}  |  Author: {WEBCURE_AUTHOR}  |  "
        f"{WEBCURE_STANDARD}  |  Generated: {scan_date}",
        ps("disc_ft", size=7, color=C_MUTED, align=TA_CENTER)))

    # ── Build ──────────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    buf.seek(0)
    return buf.read()


# ══════════════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
@login_required
def scan():
    body = request.get_json(force=True, silent=True) or {}
    url  = (body.get("url") or "").strip()
    opts = body.get("options", [])

    if not url:
        return jsonify({"error":True,"message":"Missing `url` field."}), 400
    valid, reason = validate_url(url)
    if not valid:
        return jsonify({"error":True,"message":reason}), 400

    try:
        result = run_full_scan(url, opts)
        return jsonify(result), 200
    except Exception as e:
        log.exception(f"{WEBCURE_NAME} scan failed: {e}")
        return jsonify({"error":True,"message":"Internal scan error."}), 500


@app.route("/api/report", methods=["POST"])
@login_required
def generate_report():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("url"):
        return jsonify({"error":True,"message":"No scan data provided."}), 400
    try:
        pdf_bytes = build_pdf_report(data)
        domain    = urllib.parse.urlparse(data["url"]).netloc.replace("www.","")
        date_str  = datetime.now().strftime("%Y-%m-%d")
        filename  = f"WebCure_Report_{domain}_{date_str}.pdf"
        return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                         as_attachment=True, download_name=filename)
    except Exception as e:
        log.exception(f"{WEBCURE_NAME} report failed: {e}")
        return jsonify({"error":True,"message":f"Report generation failed: {str(e)}"}), 500


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":   "ok",
        "tool":     WEBCURE_NAME,
        "version":  WEBCURE_VERSION,
        "author":   WEBCURE_AUTHOR,
        "standard": WEBCURE_STANDARD,
    }), 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    import os
    from flask import send_from_directory
    frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
    target = path if path and os.path.exists(os.path.join(frontend_dir, path)) else "index.html"
    return send_from_directory(frontend_dir, target)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"""
  ██╗    ██╗███████╗██████╗  ██████╗██╗   ██╗██████╗ ███████╗
  ██║    ██║██╔════╝██╔══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
  ██║ █╗ ██║█████╗  ██████╔╝██║     ██║   ██║██████╔╝█████╗
  ██║███╗██║██╔══╝  ██╔══██╗██║     ██║   ██║██╔══██╗██╔══╝
  ╚███╔███╔╝███████╗██████╔╝╚██████╗╚██████╔╝██║  ██║███████╗
   ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

  Project  : {WEBCURE_NAME} — {WEBCURE_TAGLINE}
  Author   : {WEBCURE_AUTHOR}
  Version  : {WEBCURE_VERSION}
  Standard : {WEBCURE_STANDARD}
  Server   : http://0.0.0.0:5000
    """)
    app.run(host="0.0.0.0", port=5000, debug=False)
