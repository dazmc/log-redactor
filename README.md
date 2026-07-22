# redact

Deterministic secret redaction for log files. Finds and replaces sensitive information (API keys, passwords, tokens, PII, connection strings) with consistent redacted placeholders using HMAC-SHA256 hashing.

Same salt + same secret = same redacted output. Works in air-gapped environments (zero external dependencies, pure stdlib only).

## Features

- **30+ detection patterns** for AWS, Azure, GCP keys, JWTs, Stripe/GitHub/Slack tokens, passwords, connection strings, PII (emails, SSNs, credit cards), PEM private keys
- **Deterministic redaction** — same input always produces same output for a given salt
- **Priority-based overlap resolution** — specific patterns (connection strings) beat generic ones (passwords) when matches overlap
- **Multi-format support** — plain text logs, JSON/JSONL, auto-detection
- **JSON structure preservation** — redacts values while keeping JSON intact
- **Configurable categories** — toggle detection for API keys, tokens, passwords, PII, network, etc.
- **Custom patterns** — extend with your own regex rules via config
- **Zero dependencies** — pure Python stdlib, works offline

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
cd log-redactor
pip install -e .
# deactivate when finished
# deactivate

# Or run directly without installing
python3 -m redactor <logfile>
```

## Quick Start

```bash
# Redact a log file (output to stdout)
redact app.log

# Redact and save to file
redact app.log clean.log

# Pipe from stdin
cat app.log | redact
cat app.log | redact -s "my-team-salt"

# JSON logs
redact --format json logs.jsonl

# Preview what would be redacted (dry run)
redact --dry-run app.log
```

## Usage

```
redact [options] [input] [output]
```

| Argument | Description |
|----------|-------------|
| `input` | Input file (default: stdin) |
| `output` | Output file (default: stdout) |
| `-s, --salt` | Salt for deterministic hashing |
| `-c, --config` | Path to config file (JSON) |
| `-f, --format` | Input format: `auto`, `text`, `json` |
| `-d, --dry-run` | Show findings without writing |
| `-q, --quiet` | Suppress summary output |
| `-v, --verbose` | Show each finding with details |
| `--list-patterns` | List all built-in patterns |
| `--list-tlds` | List TLDs matched by hostname pattern |
| `--init-config FILE` | Generate default config file |

### Category Toggles

| Flag | Description |
|------|-------------|
| `--api-keys` / `--no-api-keys` | AWS, Azure, GCP, generic API keys |
| `--tokens` / `--no-tokens` | JWT, GitHub, Slack, Stripe tokens |
| `--passwords` / `--no-passwords` | Passwords in key=value format |
| `--connection-strings` / `--no-connection-strings` | Postgres, Redis, MongoDB, JDBC URLs |
| `--pii` / `--no-pii` | Emails, SSNs, phone numbers, credit cards |
| `--private-keys` / `--no-private-keys` | PEM-encoded private keys |
| `--network` | IP addresses and internal hostnames (disabled by default) |
| `--high-entropy` / `--no-high-entropy` | Catch-all for unknown secrets |

## Examples

### Text Log

**Input:**
```
2025-07-21T10:15:33Z DEBUG Connecting to database postgres://admin:s3cretP@ss123@db.example.com:5432/myapp
2025-07-21T10:15:34Z INFO  AWS credentials loaded: access_key=AKIAIOSFODNN7EXAMPLE secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
2025-07-21T10:15:36Z INFO  User login: user=john.doe@example.com password=Sup3rS3cret!
2025-07-21T10:15:38Z INFO  JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
2025-07-21T10:15:40Z DEBUG Customer SSN: 123-45-6789, phone: (555) 867-5309
```

**Output:**
```
2025-07-21T10:15:33Z DEBUG Connecting to database REDACTED_DATABASE_URL_c50182aa
2025-07-21T10:15:34Z INFO  AWS credentials loaded: access_key=REDACTED_AWS_ACCESS_KEY_9bfce9d6 secret_access_key=REDACTED_BASE64_SECRET_2d87d87f
2025-07-21T10:15:36Z INFO  User login: user=REDACTED_EMAIL_bcdb67e2 password=REDACTED_PASSWORD_6ec3336d
2025-07-21T10:15:38Z INFO  JWT token: REDACTED_JWT_36cc47be
2025-07-21T10:15:40Z DEBUG Customer SSN: REDACTED_SSN_1fe3eab2, phone: REDACTED_PHONE_950a4fa7
```

### JSON Logs

**Input:**
```json
{"timestamp": "2025-07-21T10:15:33Z", "level": "INFO", "message": "AWS credentials loaded", "access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
{"timestamp": "2025-07-21T10:15:35Z", "level": "INFO", "message": "User login", "user": "john.doe@example.com", "password": "Sup3rS3cret!"}
```

**Output:**
```json
{"timestamp": "2025-07-21T10:15:33Z", "level": "INFO", "message": "AWS credentials loaded", "access_key": "REDACTED_AWS_ACCESS_KEY_9bfce9d6", "secret_key": "REDACTED_BASE64_SECRET_2d87d87f"}
{"timestamp": "2025-07-21T10:15:35Z", "level": "INFO", "message": "User login", "user": "REDACTED_EMAIL_bcdb67e2", "password": "REDACTED_PASSWORD_6ec3336d"}
```

JSON mode preserves structure — keys, types, and nesting remain intact.

### Dry Run

Preview what would be redacted without modifying anything:

```bash
redact --dry-run app.log
```

**Output:**
```
Found 5 secret(s):

  1. [DATABASE_URL] (line 2)
     Original:  postgres://admin:s3cretP@ss123@db.example.com:5432/myapp
     Redacted:  REDACTED_DATABASE_URL_c50182aa

  2. [AWS_ACCESS_KEY] (line 3)
     Original:  AKIAIOSFODNN7EXAMPLE
     Redacted:  REDACTED_AWS_ACCESS_KEY_9bfce9d6

  ...
```

### Deterministic Redaction

Same salt always produces same output:

```bash
$ echo "password=secret123" | redact -s "team-alpha"
password=REDACTED_PASSWORD_be434566

$ echo "password=secret123" | redact -s "team-alpha"
password=REDACTED_PASSWORD_be434566

$ echo "password=secret123" | redact -s "team-beta"
password=REDACTED_PASSWORD_6ade663e
```

Different salt → different hash. Same salt → same hash.

### Custom Salt

Use a team-specific or environment-specific salt for consistent redaction across deployments:

```bash
redact --salt "production-2025" app.log > clean.log
redact --salt "production-2025" debug.log >> clean.log  # Same secrets stay consistent
```

### Network Redaction

```bash
$ redact --network app.log
```

**Input:**
```
2025-07-21T10:15:33Z INFO  Server 192.168.1.100 connected to db.prod.internal.corp
2025-07-21T10:15:34Z INFO  IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
2025-07-21T10:15:35Z INFO  Public: www.example.com not matched
```

**Output:**
```
2025-07-21T10:15:33Z INFO  Server REDACTED_IP_ADDRESS_4a9ab4fa connected to REDACTED_HOSTNAME_5de7a41b
2025-07-21T10:15:34Z INFO  IPv6: REDACTED_IPV6_ADDRESS_72b1a053
2025-07-21T10:15:35Z INFO  Public: www.example.com not matched
```

### List Patterns

See all built-in detection patterns:

```bash
redact --list-patterns
```

**Output:**
```
Built-in Detection Patterns
============================================================

  [api_keys]
    AWS_ACCESS_KEY          AWS access key ID (AKIA...)
    AWS_SECRET_KEY          AWS secret access key
    ...
  [tokens]
    JWT_TOKEN               JSON Web Token
    GITHUB_TOKEN            GitHub personal access token
    ...
  [pii]
    EMAIL_ADDRESS           Email address
    SSN                     US Social Security Number
    ...
```

## Configuration

### Default Config

Generate a default config file:

```bash
redact --init-config config.json
```

**config.json:**
```json
{
  "salt": "CHANGE-ME-TO-A-UNIQUE-SALT",
  "categories": {
    "api_keys": true,
    "tokens": true,
    "passwords": true,
    "connection_strings": true,
    "pii": true,
    "private_keys": true,
    "network": false,
    "high_entropy": true
  },
  "high_entropy_threshold": 4.5,
  "custom_patterns": {
    "MY_INTERNAL_KEY": "MYAPP-[A-F0-9]{32}"
  }
}
```

### Custom Patterns

Add your own detection patterns via config. Each custom pattern maps a name to a regex:

```json
{
  "custom_patterns": {
    "INTERNAL_API_KEY": "INTERNAL-[a-zA-Z0-9]{32}",
    "JIRA_TICKET": "JIRA-[0-9]+",
    "AWS_ACCOUNT_ID": "[0-9]{12}"
  }
}
```

**Pattern syntax:**
- Use standard Python regex syntax
- The entire match is replaced with `REDACTED_{NAME}_{hash}`
- If your regex has a capture group `(...)`, only the captured text is replaced
- Patterns are case-insensitive by default

**Examples:**

```json
{
  "custom_patterns": {
    "COMPANY_ID": "COMPANY-[A-Z]{2}[0-9]{6}",
    "DATABASE_PASSWORD": "db_pass=([\\S]+)",
    "INTERNAL_SECRET": "SECRET-[a-f0-9]{40}"
  }
}
```

**Custom pattern priority:**

Custom patterns use priority 50 (same as passwords). To change priority, add a `priority` key:

```json
{
  "custom_patterns": {
    "CRITICAL_SECRET": {
      "regex": "CRITICAL-[A-Z0-9]{32}",
      "priority": 95
    }
  }
}
```

**Using with CLI:**

```bash
# Use config with custom patterns
redact --config my-rules.json app.log

# Or put config in ./config.json (auto-loaded)
redact app.log
```

**Using without config file:**

```bash
# Generate config with custom patterns
redact --init-config config.json
# Edit config.json to add your patterns
redact --config config.json app.log
```

### Config Resolution

Config is loaded in this order (later overrides earlier):

1. Built-in defaults
2. `./config.json` (if exists)
3. `REDACTOR_CONFIG` environment variable
4. `-c, --config` CLI flag
5. `-s, --salt` CLI flag (overrides salt only)

## Redaction Format

Redacted values follow the format:

```
REDACTED_{TYPE}_{8-char-hash}
```

Examples:
- `REDACTED_AWS_ACCESS_KEY_9bfce9d6`
- `REDACTED_PASSWORD_be434566`
- `REDACTED_EMAIL_bcdb67e2`
- `REDACTED_SSN_1fe3eab2`

The hash is derived from `HMAC-SHA256(salt, original_value)`, truncated to 8 hex characters.

## Priority System

When patterns overlap (e.g., a password that's also a high-entropy string), the highest-priority match wins:

| Priority | Pattern Type |
|----------|--------------|
| 100 | Connection strings (Postgres, Redis, MongoDB) |
| 95 | Cloud keys (AWS, Azure, GCP) |
| 90 | Tokens (JWT, GitHub, Slack, Stripe) |
| 85 | Private key blocks (PEM) |
| 80 | Credit cards |
| 75 | SSNs |
| 60 | Generic API keys |
| 50 | Passwords, custom patterns |
| 40 | Emails |
| 35 | Phone numbers |
| 30 | IP addresses |
| 25 | Hostnames |
| 10 | High-entropy catch-all |

## Supported Secret Types

| Category | Types |
|----------|-------|
| **API Keys** | AWS access/secret keys, Azure storage/client, GCP service account, generic API keys |
| **Tokens** | JWT, GitHub, GitLab, Slack, Stripe, SendGrid, Twilio, Heroku |
| **Passwords** | Key=value format, quoted values, standalone in JSON (key-aware) |
| **Connection Strings** | PostgreSQL, Redis, MongoDB, JDBC, AMQP |
| **PII** | Emails, US SSNs, phone numbers, credit cards (Visa/Mastercard/Amex/Discover) |
| **Private Keys** | RSA/EC/DSA PEM blocks, PGP private keys |
| **Network** | IPv4, IPv6, internal hostnames |
| **High Entropy** | Catch-all for unknown secrets (configurable threshold) |

## Testing

```bash
# Run against sample text log
redact tests/sample_text.log

# Run against sample JSON log
redact --format json tests/sample_json.jsonl

# Verbose output (shows each finding)
redact -v tests/sample_text.log
```

## License

MIT
