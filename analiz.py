import zxcvbn
import hashlib
import requests

def check_pwned_api(password: str) -> int:
    """
    Checks if a password has been leaked in public data breaches.
    Uses SHA-1 hashing and K-Anonymity for privacy.
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
        return 0
    except Exception:
        return 0

def sifre_analiz_et(password: str) -> dict:
    """Analyzes password strength and breach intelligence."""
    if not password:
        return {"error": "Input required"}

    # Strength Audit
    audit = zxcvbn.zxcvbn(password)
    
    # Breach Audit
    leak_count = check_pwned_api(password)

    return {
        "summary": {
            "score": audit['score'],
            "level": ["Critical", "Weak", "Fair", "Strong", "Great"][audit['score']],
            "crack_time": audit['crack_times_display']['offline_fast_hashing_1e10_per_second']
        },
        "feedback": {
            "warning": audit['feedback']['warning'],
            "suggestions": audit['feedback']['suggestions']
        },
        "intelligence": {
            "pwned": leak_count > 0,
            "count": leak_count
        }
    }