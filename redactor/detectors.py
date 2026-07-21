"""Secret detection patterns - regex catalog for common secret types.

All patterns use named groups so the engine knows what type was matched.
Each pattern is a compiled regex with a 'secret_type' attribute.
"""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Pattern:
    """A named detection pattern."""
    name: str
    regex: str
    description: str
    entropy_threshold: float = 0.0
    _compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.regex)

    def search(self, text: str):
        return self._compiled.search(text)

    def finditer(self, text: str):
        return self._compiled.finditer(text)

    def sub(self, replacement: str, text: str):
        return self._compiled.sub(replacement, text)


# ── Cloud Provider Keys ──────────────────────────────────────────────────────

AWS_ACCESS_KEY = Pattern(
    name="AWS_ACCESS_KEY",
    regex=r"\b(AKIA[0-9A-Z]{16})\b",
    description="AWS Access Key ID (AKIA prefix)",
)

AWS_SECRET_KEY = Pattern(
    name="AWS_SECRET_KEY",
    regex=r"(?i)(?:aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    description="AWS Secret Access Key (40-char base64)",
)

AWS_SESSION_TOKEN = Pattern(
    name="AWS_SESSION_TOKEN",
    regex=r"(?i)(?:aws[_\-]?session[_\-]?token|session[_\-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
    description="AWS Session Token",
)

AZURE_STORAGE_KEY = Pattern(
    name="AZURE_STORAGE_KEY",
    regex=r"(?i)(?:account[_\-]?key|storage[_\-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{86,88}==)['\"]?",
    description="Azure Storage Account Key",
)

AZURE_CLIENT_SECRET = Pattern(
    name="AZURE_CLIENT_SECRET",
    regex=r"(?i)(?:client[_\-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9~._\-]{34,40})['\"]?",
    description="Azure AD Client Secret",
)

GCP_SERVICE_ACCOUNT_KEY = Pattern(
    name="GCP_SA_KEY",
    regex=r'"private_key"\s*:\s*"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\\n[A-Za-z0-9/+=\\n]+-----END (?:RSA |EC )?PRIVATE KEY-----)"',
    description="GCP Service Account private_key field in JSON key file",
)

# ── Tokens & API Keys ────────────────────────────────────────────────────────

JWT_TOKEN = Pattern(
    name="JWT",
    regex=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
    description="JSON Web Token (JWT)",
)

GITHUB_TOKEN = Pattern(
    name="GITHUB_TOKEN",
    regex=r"(?:ghp|gho|ghu|ghs|ghr|ghp|github_pat)_[A-Za-z0-9_]{36,255}",
    description="GitHub personal access token / OAuth token",
)

GITLAB_TOKEN = Pattern(
    name="GITLAB_TOKEN",
    regex=r"glpat-[A-Za-z0-9\-_]{20,}",
    description="GitLab personal access token",
)

SLACK_TOKEN = Pattern(
    name="SLACK_TOKEN",
    regex=r"xox[bpsar]-[0-9]{10,13}-[0-9a-zA-Z\-]{20,}",
    description="Slack bot/user/app token",
)

STRIPE_KEY = Pattern(
    name="STRIPE_KEY",
    regex=r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99}",
    description="Stripe API key (live or test)",
)

SENDGRID_KEY = Pattern(
    name="SENDGRID_KEY",
    regex=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    description="SendGrid API key",
)

TWILIO_SID = Pattern(
    name="TWILIO_SID",
    regex=r"AC[a-f0-9]{32}",
    description="Twilio Account SID",
)

HEROKU_API_KEY = Pattern(
    name="HEROKU_API_KEY",
    regex=r"(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
    description="Heroku API key",
)

# ── Passwords & Secrets in Key=Value ────────────────────────────────────────

PASSWORD_VALUE = Pattern(
    name="PASSWORD",
    regex=r"(?i)(?:password|passwd|pwd|pass|secret|token|auth_token|access_token|refresh_token|private_key|credentials)\s*[:=]\s*['\"]?(\S{3,})['\"]?",
    description="Password or secret value in key=value format",
)

QUOTED_PASSWORD = Pattern(
    name="QUOTED_PASSWORD",
    regex=r"(?i)(?:password|passwd|pwd|pass|secret|token)\s*[:=]\s*['\"]([^'\"]{3,})['\"]",
    description="Quoted password/secret value",
)

# ── Connection Strings ───────────────────────────────────────────────────────

JDBC_URL = Pattern(
    name="JDBC_URL",
    regex=r"jdbc:[a-z]+://[^\s'\"]+",
    description="JDBC connection string",
)

MONGODB_URL = Pattern(
    name="MONGODB_URL",
    regex=r"mongodb(?:\+srv)?://[^\s'\"]+",
    description="MongoDB connection string",
)

REDIS_URL = Pattern(
    name="REDIS_URL",
    regex=r"rediss?://[^\s'\"]+",
    description="Redis connection string",
)

DATABASE_URL = Pattern(
    name="DATABASE_URL",
    regex=r"(?:postgres|mysql|MariaDB|mssql)://[^\s'\"]+",
    description="PostgreSQL/MySQL/MariaDB/MSSQL connection string",
)

AMQP_URL = Pattern(
    name="AMQP_URL",
    regex=r"amqps?://[^\s'\"]+",
    description="AMQP/RabbitMQ connection string",
)

# ── PII ──────────────────────────────────────────────────────────────────────

EMAIL_ADDRESS = Pattern(
    name="EMAIL",
    regex=r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    description="Email address",
)

SSN = Pattern(
    name="SSN",
    regex=r"(?<!\d)[0-9]{3}-[0-9]{2}-[0-9]{4}(?!\d)",
    description="US Social Security Number (XXX-XX-XXXX)",
)

PHONE_NUMBER = Pattern(
    name="PHONE",
    regex=r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)[0-9]{3}[-.\s]?[0-9]{4}(?!\d)",
    description="US phone number",
)

CREDIT_CARD = Pattern(
    name="CREDIT_CARD",
    regex=r"(?<!\d)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?!\d)",
    description="Credit card number (Visa/Mastercard/Amex/Discover)",
)

IPV4_ADDRESS = Pattern(
    name="IP_ADDRESS",
    regex=r"(?<!\d)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\d)",
    description="IPv4 address",
)

IPV6_ADDRESS = Pattern(
    name="IPV6_ADDRESS",
    regex=r"(?<![0-9a-fA-F:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)(?![0-9a-fA-F:])",
    description="IPv6 address",
)

HOSTNAME = Pattern(
    name="HOSTNAME",
    regex=r"(?<![a-zA-Z0-9\-])(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,10}(?:internal|local|corp|company|private|intranet|lan|net|uk|localhost|home|lab|dev|staging|prod|production))(?![a-zA-Z0-9\-])",
    description="Internal hostname (e.g., server.internal.corp, db.staging.company, host.office.uk)",
)

# ── Cryptographic Keys ───────────────────────────────────────────────────────

RSA_PRIVATE_KEY = Pattern(
    name="RSA_PRIVATE_KEY",
    regex=r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----",
    description="PEM-encoded private key block",
)

PGP_PRIVATE_KEY = Pattern(
    name="PGP_PRIVATE_KEY",
    regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----",
    description="PGP private key block",
)

# ── Generic Key Patterns ─────────────────────────────────────────────────────

GENERIC_API_KEY = Pattern(
    name="GENERIC_API_KEY",
    regex=r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?key|app[_\-]?secret|access[_\-]?key|secret[_\-]?key|encryption[_\-]?key|signing[_\-]?key|auth[_\-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{16,})['\"]?",
    description="Generic API key / secret in key=value format",
)

HEX_SECRET = Pattern(
    name="HEX_SECRET",
    regex=r"(?i)(?:secret|key|token|salt|hash)\s*[:=]\s*['\"]?([0-9a-f]{32,})['\"]?",
    description="Hex-encoded secret (32+ hex chars after key label)",
)

BASE64_SECRET = Pattern(
    name="BASE64_SECRET",
    regex=r"(?i)(?:secret|key|token|credential)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40,}={0,2})['\"]?",
    description="Base64-encoded secret (40+ chars after key label)",
)

# ── High Entropy Catch-All ───────────────────────────────────────────────────

HIGH_ENTROPY = Pattern(
    name="HIGH_ENTROPY",
    regex=r"[A-Za-z0-9+/=_\-]{32,}",
    description="High-entropy string (catches unknown secrets, filtered by entropy threshold at runtime)",
)


# ── Pattern Groups ───────────────────────────────────────────────────────────

PATTERN_GROUPS = {
    "api_keys": [
        AWS_ACCESS_KEY,
        AWS_SECRET_KEY,
        AWS_SESSION_TOKEN,
        AZURE_STORAGE_KEY,
        AZURE_CLIENT_SECRET,
        GCP_SERVICE_ACCOUNT_KEY,
        GENERIC_API_KEY,
        HEX_SECRET,
        BASE64_SECRET,
    ],
    "tokens": [
        JWT_TOKEN,
        GITHUB_TOKEN,
        GITLAB_TOKEN,
        SLACK_TOKEN,
        STRIPE_KEY,
        SENDGRID_KEY,
        TWILIO_SID,
        HEROKU_API_KEY,
    ],
    "passwords": [
        PASSWORD_VALUE,
        QUOTED_PASSWORD,
    ],
    "connection_strings": [
        JDBC_URL,
        MONGODB_URL,
        REDIS_URL,
        DATABASE_URL,
        AMQP_URL,
    ],
    "pii": [
        EMAIL_ADDRESS,
        SSN,
        PHONE_NUMBER,
        CREDIT_CARD,
    ],
    "private_keys": [
        RSA_PRIVATE_KEY,
        PGP_PRIVATE_KEY,
    ],
    "network": [
        IPV4_ADDRESS,
        IPV6_ADDRESS,
        HOSTNAME,
    ],
    "high_entropy": [
        HIGH_ENTROPY,
    ],
}


def get_all_patterns() -> List[Pattern]:
    """Return a flat list of all patterns."""
    patterns = []
    for group_patterns in PATTERN_GROUPS.values():
        patterns.extend(group_patterns)
    return patterns


def get_patterns_for_categories(categories: dict) -> List[Pattern]:
    """Return patterns for enabled categories only.

    Args:
        categories: dict mapping category name to bool (enabled/disabled)
    """
    patterns = []
    for category, enabled in categories.items():
        if enabled and category in PATTERN_GROUPS:
            patterns.extend(PATTERN_GROUPS[category])
    return patterns


def entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    import math
    return -sum((count / length) * math.log2(count / length) for count in freq.values())
