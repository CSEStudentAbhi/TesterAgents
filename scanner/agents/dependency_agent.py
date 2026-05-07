import re
import json

AGENT_NAME = "Dependency"

RULES = [
    {
        "id": "DEP001",
        "name": "Missing Helmet Middleware",
        "severity": "warning",
        "check": "missing_helmet",
        "message": "Helmet middleware is not used. Helmet sets security-related HTTP headers."
    },
    {
        "id": "DEP002",
        "name": "Missing Rate Limiting",
        "severity": "warning",
        "check": "missing_rate_limit",
        "message": "No rate-limiting middleware found. Add express-rate-limit to prevent brute force attacks."
    },
    {
        "id": "DEP003",
        "name": "No Input Validation Library",
        "severity": "info",
        "check": "missing_validator",
        "message": "No input validation library (joi, express-validator, zod) found in dependencies."
    },
    {
        "id": "DEP004",
        "name": "Debug Mode Enabled in Production",
        "severity": "critical",
        "pattern": re.compile(r'NODE_ENV\s*=\s*development|debug\s*[:=]\s*true', re.IGNORECASE),
        "message": "Debug/development mode may be enabled. Ensure NODE_ENV=production in deployment.",
        "extensions": {".env", ""}
    },
    {
        "id": "DEP005",
        "name": "Missing HTTPS Enforcement",
        "severity": "info",
        "check": "missing_https",
        "message": "No HTTPS enforcement detected in main server file. Ensure HTTPS in production."
    },
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def _check_package_json(abs_path, rel_path, content):
    issues = []
    if "package.json" not in abs_path:
        return issues

    try:
        pkg = json.loads(content)
    except Exception:
        return issues

    deps = {}
    deps.update(pkg.get("dependencies", {}))
    deps.update(pkg.get("devDependencies", {}))

    dep_names = [k.lower() for k in deps.keys()]

    # DEP001 - helmet
    if not any("helmet" in d for d in dep_names):
        issues.append({
            "agent": AGENT_NAME, "rule_id": "DEP001",
            "rule_name": "Missing Helmet Middleware",
            "severity": "warning",
            "message": "Helmet is not in dependencies. Add 'helmet' to secure HTTP headers.",
            "file": rel_path, "line": 1, "snippet": "package.json"
        })

    # DEP002 - rate limit
    if not any("rate" in d or "limiter" in d for d in dep_names):
        issues.append({
            "agent": AGENT_NAME, "rule_id": "DEP002",
            "rule_name": "Missing Rate Limiting",
            "severity": "warning",
            "message": "No rate-limiting package found. Add 'express-rate-limit'.",
            "file": rel_path, "line": 1, "snippet": "package.json"
        })

    # DEP003 - validator
    validation_libs = ["joi", "express-validator", "zod", "yup", "ajv", "validate.js"]
    if not any(lib in dep_names for lib in validation_libs):
        issues.append({
            "agent": AGENT_NAME, "rule_id": "DEP003",
            "rule_name": "No Input Validation Library",
            "severity": "info",
            "message": "No input validation library found. Consider adding 'joi' or 'express-validator'.",
            "file": rel_path, "line": 1, "snippet": "package.json"
        })

    return issues


def _check_server_file(abs_path, rel_path, content, lines):
    """Check for security patterns in the main server entry file."""
    issues = []
    is_entry = any(name in abs_path for name in ["index.js", "server.js", "app.js", "main.js"])
    if not is_entry:
        return issues

    # DEP005 - https enforcement
    has_https = bool(re.search(r'\bhttps\b|\bsecure\b|\bssl\b', content, re.IGNORECASE))
    if not has_https:
        issues.append({
            "agent": AGENT_NAME, "rule_id": "DEP005",
            "rule_name": "Missing HTTPS Enforcement",
            "severity": "info",
            "message": "No HTTPS / SSL reference found in server file. Enforce HTTPS in production.",
            "file": rel_path, "line": 1, "snippet": abs_path.split("\\")[-1].split("/")[-1]
        })

    return issues


# ── Main scan ─────────────────────────────────────────────────────────────────

def scan(abs_path, rel_path, content, lines):
    issues = []
    ext = "." + abs_path.rsplit(".", 1)[-1].lower() if "." in abs_path else ""
    filename = abs_path.replace("\\", "/").split("/")[-1]

    # package.json specific checks
    if filename == "package.json":
        issues.extend(_check_package_json(abs_path, rel_path, content))

    # Server entry file checks
    if ext in {".js", ".ts"}:
        issues.extend(_check_server_file(abs_path, rel_path, content, lines))

    # Pattern-based rules on .env files
    for rule in RULES:
        pattern = rule.get("pattern")
        if not pattern:
            continue
        rule_exts = rule.get("extensions", set())
        if ext not in rule_exts and filename not in {".env", ".env.local"}:
            continue
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                issues.append({
                    "agent": AGENT_NAME, "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "file": rel_path, "line": i,
                    "snippet": line.strip()[:120]
                })

    return issues
