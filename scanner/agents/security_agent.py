import re

AGENT_NAME = "Security"

# ── Password check (file-level, smarter) ─────────────────────────────────────

def _check_unencrypted_password(lines, rel_path, content):
    """
    Detect password saved to DB without hashing.
    Catches all forms:
      - password: req.body.password
      - const { password } = req.body  ...  new User({ password })
      - user.password = plainText  ...  user.save()
    """
    issues = []

    # Only check files that deal with password at all
    if not re.search(r'\bpassword\b', content, re.IGNORECASE):
        return issues

    # Is any real hashing library used in this file?
    has_hashing = bool(re.search(
        r'bcrypt\.(hash|hashSync|genSalt)|argon2|crypto\.pbkdf2|scrypt|\.hash\s*\(',
        content, re.IGNORECASE
    ))

    # Does the file perform a DB write?
    has_db_write = bool(re.search(
        r'\.(save|create|insertOne|insertMany|findOneAndUpdate|updateOne|findByIdAndUpdate|upsertOne)\s*\(',
        content, re.IGNORECASE
    ))

    # Does the file receive password from user input?
    has_user_input_password = bool(re.search(
        r'req\.(body|query|params).*password'
        r'|const\s*\{[^}]*password[^}]*\}\s*=\s*req\.(body|query|params)',
        content, re.IGNORECASE | re.DOTALL
    ))

    if has_user_input_password and has_db_write and not has_hashing:
        # Find the most relevant line to report
        for i, line in enumerate(lines, 1):
            if re.search(
                r'(req\.(body|query|params).*password|password.*req\.(body|query|params))',
                line, re.IGNORECASE
            ):
                issues.append({
                    "agent": AGENT_NAME,
                    "rule_id": "SEC001",
                    "rule_name": "Unencrypted Password Storage",
                    "severity": "critical",
                    "message": (
                        "Password from user input is being saved to the database WITHOUT hashing. "
                        "Use bcrypt.hash(password, saltRounds) before storing."
                    ),
                    "file": rel_path,
                    "line": i,
                    "snippet": line.strip()[:120]
                })
                break  # One report per file is enough

    return issues


# ── Rule table (pattern-based) ────────────────────────────────────────────────

RULES = [
    # SEC001 handled by _check_unencrypted_password above
    {
        "id": "SEC002",
        "name": "Hardcoded Secret / API Key",
        "severity": "critical",
        "pattern": re.compile(
            r'(secret\s*[:=]\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']'
            r'|api[_\-]?key\s*[:=]\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']'
            r'|private[_\-]?key\s*[:=]\s*["\'][^"\']{8,}["\']'
            r'|token\s*[:=]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\'])',
            re.IGNORECASE
        ),
        "message": "Hardcoded secret/API key detected. Move this to environment variables (.env).",
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".py"}
    },
    {
        "id": "SEC003",
        "name": "eval() Usage",
        "severity": "critical",
        "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
        "message": "eval() is dangerous and can lead to code injection attacks. Never use eval().",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
    {
        "id": "SEC004",
        "name": "JWT Signed Without Expiry",
        "severity": "critical",
        "extensions": {".js", ".ts"},
        "check": "jwt_no_expiry"
    },
    {
        "id": "SEC005",
        "name": "CORS Wildcard Origin",
        "severity": "warning",
        "pattern": re.compile(
            r'cors\s*\(\s*\{\s*origin\s*:\s*["\'][*]["\']'
            r'|cors\s*\(\s*["\'][*]["\']',
            re.IGNORECASE
        ),
        "message": "CORS allows all origins ('*'). Restrict to specific trusted domains.",
        "extensions": {".js", ".ts"}
    },
    {
        "id": "SEC006",
        "name": "Sensitive Data in console.log",
        "severity": "warning",
        "pattern": re.compile(
            r'console\.(log|warn|info)\s*\([^)]*?(password|token|secret|apikey|api_key|auth)[^)]*\)',
            re.IGNORECASE
        ),
        "message": "Sensitive data (password/token/secret) being logged. Remove before production.",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
    {
        "id": "SEC007",
        "name": "MD5 Used for Security",
        "severity": "warning",
        "pattern": re.compile(r'\bmd5\s*\(', re.IGNORECASE),
        "message": "MD5 is cryptographically broken. Use bcrypt for passwords or SHA-256 for other hashing.",
        "extensions": {".js", ".ts", ".py"}
    },
    {
        "id": "SEC008",
        "name": "NoSQL Injection Risk ($where)",
        "severity": "critical",
        "pattern": re.compile(r'\$where\s*:', re.IGNORECASE),
        "message": "Potential NoSQL injection via $where. Never use $where with user-supplied data.",
        "extensions": {".js", ".ts"}
    },
    {
        "id": "SEC009",
        "name": ".env File Committed to Repository",
        "severity": "critical",
        "pattern": re.compile(r'.+', re.DOTALL),
        "message": ".env file detected inside the uploaded project. NEVER commit .env to version control. Add it to .gitignore.",
        "extensions": set(),
        "filenames": {".env", ".env.local", ".env.production", ".env.development"}
    },
    {
        "id": "SEC010",
        "name": "Raw User Input Without Sanitization",
        "severity": "warning",
        "pattern": re.compile(
            r'req\.(body|query|params)\.\w+\s*[,;)\]](?!\s*\.\s*(trim|replace|sanitize|escape|validate|match))',
            re.IGNORECASE
        ),
        "message": "User input used directly without sanitization. Validate and sanitize all inputs.",
        "extensions": {".js", ".ts"}
    },
    {
        "id": "SEC011",
        "name": "Password Compared in Plain Text",
        "severity": "critical",
        "pattern": re.compile(
            r'(password\s*[=!]=+\s*req\.(body|query)\.\w+'
            r'|req\.(body|query)\.\w+\s*[=!]=+\s*password'
            r'|password\s*[=!]=+\s*["\'][^"\']+["\'])',
            re.IGNORECASE
        ),
        "message": "Password is being compared in plain text. Use bcrypt.compare() instead.",
        "extensions": {".js", ".ts"}
    },
    {
        "id": "SEC012",
        "name": "Mongoose Schema — Password Not Excluded from Queries",
        "severity": "warning",
        "pattern": re.compile(r'password\s*:\s*\{[^}]*type\s*:\s*String(?![^}]*select\s*:\s*false)', re.IGNORECASE | re.DOTALL),
        "message": "Password field in Mongoose schema lacks 'select: false'. It will be returned in all queries.",
        "extensions": {".js", ".ts"}
    },
]


# ── JWT check ────────────────────────────────────────────────────────────────

_jwt_sign_re = re.compile(r'jwt\.sign\s*\(([^;]{0,300})', re.IGNORECASE | re.DOTALL)

def _check_jwt(lines, rel_path, content):
    issues = []
    for i, line in enumerate(lines, 1):
        if re.search(r'jwt\.sign\s*\(', line, re.IGNORECASE):
            # Grab next few lines to check for expiresIn
            window = "\n".join(lines[i-1:i+6])
            if "expiresIn" not in window and "expiresIn" not in window.replace(" ", ""):
                issues.append({
                    "agent": AGENT_NAME,
                    "rule_id": "SEC004",
                    "rule_name": "JWT Signed Without Expiry",
                    "severity": "critical",
                    "message": "JWT is signed without expiresIn. Tokens that never expire are a major security risk.",
                    "file": rel_path,
                    "line": i,
                    "snippet": line.strip()[:120]
                })
    return issues


# ── Main scan ─────────────────────────────────────────────────────────────────

def scan(abs_path, rel_path, content, lines):
    issues = []
    ext      = ("." + abs_path.rsplit(".", 1)[-1].lower()) if "." in abs_path else ""
    filename = abs_path.replace("\\", "/").split("/")[-1]

    # File-level smart checks
    if ext in {".js", ".ts", ".jsx", ".tsx"}:
        issues.extend(_check_unencrypted_password(lines, rel_path, content))

    # Pattern-based rules
    for rule in RULES:
        # .env filename special case
        if rule.get("filenames") and filename in rule["filenames"]:
            issues.append({
                "agent": AGENT_NAME,
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "message": rule["message"],
                "file": rel_path,
                "line": 1,
                "snippet": lines[0].strip() if lines else ""
            })
            continue

        if ext not in rule.get("extensions", set()):
            continue

        check = rule.get("check")
        if check == "jwt_no_expiry":
            issues.extend(_check_jwt(lines, rel_path, content))
            continue

        pattern = rule.get("pattern")
        if pattern:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    issues.append({
                        "agent": AGENT_NAME,
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "message": rule["message"],
                        "file": rel_path,
                        "line": i,
                        "snippet": line.strip()[:120]
                    })

    return issues
