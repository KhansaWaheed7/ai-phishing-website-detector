import re
import urllib.parse
from datetime import datetime

def extract_features(url):

    features = []

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        full_url = url
    except Exception:
        # Return worst-case features if parsing fails
        return [-1] * 15

    # 1. URL Length (longer = more suspicious)
    url_len = len(full_url)
    if url_len < 54:
        features.append(1)
    elif url_len <= 75:
        features.append(0)
    else:
        features.append(-1)

    # 2. Has IP address instead of domain
    ip_pattern = re.compile(
        r"(\d{1,3}\.){3}\d{1,3}"
    )
    if ip_pattern.search(domain):
        features.append(-1)
    else:
        features.append(1)

    # 3. @ symbol in URL (tricks browser to use different host)
    features.append(-1 if "@" in full_url else 1)

    # 4. Double slash redirect (//)
    # Legit sites rarely have // after the initial protocol
    pos = full_url.rfind("//")
    if pos > 6:
        features.append(-1)
    else:
        features.append(1)

    # 5. Dash (-) in domain name
    features.append(-1 if "-" in domain else 1)

    # 6. Number of subdomains (dots in domain)
    dot_count = domain.count(".")
    if dot_count == 1:
        features.append(1)
    elif dot_count == 2:
        features.append(0)
    else:
        features.append(-1)

    # 7. HTTPS protocol
    features.append(1 if parsed.scheme == "https" else -1)

    # 8. Domain length
    if len(domain) < 20:
        features.append(1)
    elif len(domain) <= 30:
        features.append(0)
    else:
        features.append(-1)

    # 9. Number of digits in URL
    digit_count = sum(c.isdigit() for c in full_url)
    digit_ratio = digit_count / max(len(full_url), 1)
    if digit_ratio < 0.1:
        features.append(1)
    elif digit_ratio < 0.2:
        features.append(0)
    else:
        features.append(-1)

    # 10. Suspicious keywords in URL
    suspicious_words = [
        "secure", "account", "update", "login", "signin",
        "banking", "confirm", "verify", "paypal", "ebay",
        "free", "prize", "winner", "click", "password"
    ]
    found = sum(1 for word in suspicious_words if word in full_url.lower())
    if found == 0:
        features.append(1)
    elif found == 1:
        features.append(0)
    else:
        features.append(-1)

    # 11. Port in URL (non-standard port = suspicious)
    if parsed.port and parsed.port not in (80, 443):
        features.append(-1)
    else:
        features.append(1)

    # 12. Path length
    if len(path) < 20:
        features.append(1)
    elif len(path) < 60:
        features.append(0)
    else:
        features.append(-1)

    # 13. Query string presence and length
    query = parsed.query
    if not query:
        features.append(1)
    elif len(query) < 30:
        features.append(0)
    else:
        features.append(-1)

    # 14. Number of special characters
    special_chars = sum(1 for c in full_url if c in "!$&'()*+,;=%~")
    if special_chars < 3:
        features.append(1)
    elif special_chars < 7:
        features.append(0)
    else:
        features.append(-1)

    # 15. TLD analysis (suspicious TLDs)
    suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
        ".xyz", ".top", ".loan", ".win", ".racing"
    ]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        features.append(-1)
    else:
        features.append(1)

    return features


FEATURE_NAMES = [
    "URL Length",
    "IP Address in URL",
    "@ Symbol",
    "Double Slash Redirect",
    "Dash in Domain",
    "Subdomain Count",
    "HTTPS Protocol",
    "Domain Length",
    "Digit Ratio",
    "Suspicious Keywords",
    "Non-Standard Port",
    "Path Length",
    "Query String",
    "Special Characters",
    "Suspicious TLD",
]
