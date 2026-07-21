"""Core redaction engine - deterministic hashing and pattern matching.

Uses a two-phase approach:
1. Collect all matches from all patterns (non-destructive)
2. Resolve overlaps by priority, then apply replacements end-to-start
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .detectors import Pattern, entropy, get_patterns_for_categories


# Pattern priority: higher = more specific, wins in overlap conflicts
PRIORITY = {
    # Connection strings (full URLs - highest priority)
    "JDBC_URL": 100,
    "MONGODB_URL": 100,
    "REDIS_URL": 100,
    "DATABASE_URL": 100,
    "AMQP_URL": 100,
    # Specific cloud provider keys
    "AWS_ACCESS_KEY": 95,
    "AWS_SECRET_KEY": 95,
    "AWS_SESSION_TOKEN": 95,
    "AZURE_STORAGE_KEY": 95,
    "AZURE_CLIENT_SECRET": 95,
    "GCP_SA_KEY": 95,
    # Specific tokens
    "JWT": 90,
    "GITHUB_TOKEN": 90,
    "GITLAB_TOKEN": 90,
    "SLACK_TOKEN": 90,
    "STRIPE_KEY": 90,
    "SENDGRID_KEY": 90,
    "TWILIO_SID": 90,
    "HEROKU_API_KEY": 90,
    # Private key blocks
    "RSA_PRIVATE_KEY": 85,
    "PGP_PRIVATE_KEY": 85,
    # Credit cards
    "CREDIT_CARD": 80,
    # SSN
    "SSN": 75,
    # Generic API keys (more specific than PASSWORD)
    "GENERIC_API_KEY": 60,
    "HEX_SECRET": 60,
    "BASE64_SECRET": 55,
    # Passwords and secrets in key=value
    "PASSWORD": 50,
    "QUOTED_PASSWORD": 50,
    # PII (lower priority - can match inside other patterns)
    "EMAIL": 40,
    "PHONE": 35,
    "IP_ADDRESS": 30,
    "IPV6_ADDRESS": 30,
    "HOSTNAME": 25,
    # High entropy catch-all (lowest)
    "HIGH_ENTROPY": 10,
}

DEFAULT_PRIORITY = 50


@dataclass
class CandidateMatch:
    """A potential secret match with metadata for conflict resolution."""
    pattern_name: str
    value: str
    start: int
    end: int
    priority: int

    @property
    def length(self):
        return self.end - self.start


class Redactor:
    """Deterministic secret redaction engine.

    Uses HMAC-SHA256 with a salt to produce consistent redacted tokens.
    The same salt + same secret always produces the same redacted output.
    """

    DEFAULT_SALT = "log-redactor-default-salt"
    HASH_PREFIX_LENGTH = 8

    def __init__(self, salt: str = DEFAULT_SALT, categories: Optional[dict] = None,
                 custom_patterns: Optional[dict] = None,
                 high_entropy_threshold: float = 4.5):
        """Initialize the redactor.

        Args:
            salt: Salt for deterministic HMAC hashing.
            categories: Dict of category name -> enabled bool.
            custom_patterns: Dict of pattern name -> regex string.
            high_entropy_threshold: Minimum entropy to flag a string as high-entropy.
        """
        self.salt = salt.encode("utf-8")
        self.high_entropy_threshold = high_entropy_threshold

        # Load built-in patterns based on enabled categories
        if categories is None:
            categories = {
                "api_keys": True, "tokens": True, "passwords": True,
                "connection_strings": True, "pii": True, "private_keys": True,
                "network": False, "high_entropy": True,
            }

        self.patterns: List[Pattern] = get_patterns_for_categories(categories)

        # Add custom patterns
        if custom_patterns:
            for name, value in custom_patterns.items():
                if isinstance(value, dict):
                    # Dict format: {"regex": "...", "priority": 95}
                    regex = value["regex"]
                    priority = value.get("priority", 65)
                else:
                    # Simple format: "regex..."
                    regex = value
                    priority = 65
                self.patterns.append(Pattern(name=name, regex=regex, description=f"Custom pattern: {name}"))
                PRIORITY[name] = priority

        # Separate high-entropy pattern for special handling
        self._high_entropy_pattern = None
        self._non_entropy_patterns: List[Pattern] = []
        for p in self.patterns:
            if p.name == "HIGH_ENTROPY":
                self._high_entropy_pattern = p
            else:
                self._non_entropy_patterns.append(p)

        # Cache of already-computed redactions for consistency within a run
        self._redaction_cache: Dict[str, str] = {}

    def _compute_redacted_token(self, secret_type: str, value: str) -> str:
        """Compute a deterministic redacted token.

        Format: REDACTED_{TYPE}_{8-char-hmac-hash}
        """
        cache_key = f"{secret_type}:{value}"
        if cache_key in self._redaction_cache:
            return self._redaction_cache[cache_key]

        mac = hmac.new(self.salt, value.encode("utf-8"), hashlib.sha256)
        hash_prefix = mac.hexdigest()[:self.HASH_PREFIX_LENGTH]
        token = f"REDACTED_{secret_type}_{hash_prefix}"

        self._redaction_cache[cache_key] = token
        return token

    def _extract_match_value(self, pattern: Pattern, match: re.Match) -> str:
        """Extract the secret value from a regex match.

        Rules:
        - If pattern has capturing groups, use the LAST group (the actual secret)
        - Otherwise use the full match
        """
        if match.lastindex:
            return match.group(match.lastindex)
        return match.group(0)

    def _extract_full_match(self, pattern: Pattern, match: re.Match) -> Tuple[int, int, str]:
        """Extract the full match span and value.

        Returns (start, end, secret_value) where start/end cover the
        full extent that should be replaced.
        """
        # For patterns with groups, we want to replace just the captured value
        # But for patterns that match full constructs (URLs, key blocks),
        # we want to replace the entire match
        full_start = match.start()
        full_end = match.end()

        if match.lastindex:
            # Get the span of the last captured group
            group_start, group_end = match.span(match.lastindex)
            secret_value = match.group(match.lastindex)
            return group_start, group_end, secret_value

        return full_start, full_end, match.group(0)

    def redact_text(self, text: str) -> Tuple[str, List[dict]]:
        """Redact secrets using two-phase approach.

        Phase 1: Collect all candidate matches from ALL patterns (including high-entropy)
        Phase 2: Resolve overlaps by priority, apply replacements end-to-start

        Returns:
            Tuple of (redacted_text, list_of_findings)
        """
        if not text:
            return text, []

        # Phase 1: Collect all candidates from original text
        candidates = self._collect_candidates(text)

        # Phase 2: Resolve overlaps
        resolved = self._resolve_overlaps(candidates)

        # Phase 3: Apply replacements from end to start
        result = text
        findings = []

        for candidate in resolved:
            redacted = self._compute_redacted_token(candidate.pattern_name, candidate.value)
            findings.append({
                "type": candidate.pattern_name,
                "original": candidate.value,
                "redacted": redacted,
                "position": candidate.start,
            })
            result = result[:candidate.start] + redacted + result[candidate.end:]

        return result, findings

    def _collect_candidates(self, text: str) -> List[CandidateMatch]:
        """Phase 1: Collect all candidate matches from all patterns (including high-entropy).

        High-entropy candidates that overlap with higher-priority patterns
        will be eliminated during overlap resolution.
        """
        candidates = []

        # Collect non-entropy patterns
        for pattern in self._non_entropy_patterns:
            for match in pattern.finditer(text):
                start, end, value = self._extract_full_match(pattern, match)
                priority = PRIORITY.get(pattern.name, DEFAULT_PRIORITY)
                candidates.append(CandidateMatch(
                    pattern_name=pattern.name,
                    value=value,
                    start=start,
                    end=end,
                    priority=priority,
                ))

        # Collect high-entropy candidates from ORIGINAL text
        if self._high_entropy_pattern:
            for match in self._high_entropy_pattern.finditer(text):
                candidate = match.group(0)
                # Skip strings that are too short or look like non-secrets
                if len(candidate) < 32:
                    continue
                if self._is_likely_not_secret(candidate):
                    continue
                if entropy(candidate) < self.high_entropy_threshold:
                    continue
                priority = PRIORITY.get("HIGH_ENTROPY", DEFAULT_PRIORITY)
                candidates.append(CandidateMatch(
                    pattern_name="HIGH_ENTROPY",
                    value=candidate,
                    start=match.start(),
                    end=match.end(),
                    priority=priority,
                ))

        return candidates

    def _resolve_overlaps(self, candidates: List[CandidateMatch]) -> List[CandidateMatch]:
        """Phase 2: Resolve overlapping matches - higher priority wins.

        Sort by priority (descending), then by position.
        When two matches overlap, keep the higher priority one.
        If same priority, keep the longer match.
        """
        if not candidates:
            return []

        # Sort by priority descending, then by start position
        candidates.sort(key=lambda c: (-c.priority, c.start))

        resolved = []
        occupied = []  # List of (start, end) ranges already taken

        for candidate in candidates:
            # Check if this candidate overlaps with any already-accepted match
            overlaps = False
            for occ_start, occ_end in occupied:
                if candidate.start < occ_end and candidate.end > occ_start:
                    overlaps = True
                    break

            if not overlaps:
                resolved.append(candidate)
                occupied.append((candidate.start, candidate.end))

        # Re-sort by position DESCENDING for end-to-start replacement
        # This ensures earlier positions don't shift when later ones are replaced
        resolved.sort(key=lambda c: c.start, reverse=True)
        return resolved

    def _is_likely_not_secret(self, text: str) -> bool:
        """Heuristic check if a high-entropy string is probably not a secret."""
        lower = text.lower()
        not_secrets = [
            "begin ", "end ", "header", "content-type", "application/",
            "text/html", "charset=", "boundary=", "multipart/",
            "http/", "user-agent", "accept-", "transfer-encoding",
            "chunked", "keep-alive", "close", "iso-8859", "utf-8",
        ]
        for ns in not_secrets:
            if ns in lower:
                return True
        return False

    def find_secrets(self, text: str) -> List[dict]:
        """Find all secrets in text without redacting. Returns list of findings."""
        _, findings = self.redact_text(text)
        return findings
