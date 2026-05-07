import re

AGENT_NAME = "Dead Code"

RULES = [
    {
        "id": "DC001",
        "name": "Unused Import (require)",
        "severity": "info",
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "check": "unused_require"
    },
    {
        "id": "DC002",
        "name": "Unused ES6 Import",
        "severity": "info",
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "check": "unused_import"
    },
    {
        "id": "DC003",
        "name": "TODO / FIXME Comment",
        "severity": "info",
        "pattern": re.compile(r'(//|#)\s*(TODO|FIXME|HACK|XXX)\b', re.IGNORECASE),
        "message": "Found TODO/FIXME/HACK comment. Address or remove before release.",
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".py"}
    },
    {
        "id": "DC004",
        "name": "Large Commented-Out Code Block",
        "severity": "info",
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "check": "commented_block"
    },
    {
        "id": "DC005",
        "name": "Dead Condition (if true / if false)",
        "severity": "warning",
        "pattern": re.compile(r'\bif\s*\(\s*(true|false)\s*\)', re.IGNORECASE),
        "message": "Dead condition found: if(true) or if(false) is always resolved. Remove it.",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
    {
        "id": "DC006",
        "name": "Unused Variable (var/let/const declared but never used)",
        "severity": "info",
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "check": "unused_variable"
    },
]

# ── Helpers ──────────────────────────────────────────────────────────────────

_require_re = re.compile(r'(?:const|let|var)\s+\{?(\w+)\}?\s*=\s*require\s*\(', re.IGNORECASE)
_import_re  = re.compile(r'import\s+(?:\{[^}]+\}|(\w+))\s+from\s+["\']', re.IGNORECASE)
_import_named_re = re.compile(r'import\s+\{([^}]+)\}\s+from', re.IGNORECASE)
_varname_re = re.compile(r'(?:const|let|var)\s+(\w+)\s*=', re.IGNORECASE)


def _check_unused_require(lines, rel_path):
    issues = []
    content = "\n".join(lines)
    for i, line in enumerate(lines, 1):
        m = _require_re.search(line)
        if m:
            name = m.group(1)
            # Count usages outside the declaration line
            usages = len(re.findall(r'\b' + re.escape(name) + r'\b', content)) - 1
            if usages == 0:
                issues.append({
                    "agent": AGENT_NAME, "rule_id": "DC001",
                    "rule_name": "Unused Import (require)",
                    "severity": "info",
                    "message": f"'{name}' is imported via require() but never used.",
                    "file": rel_path, "line": i, "snippet": line.strip()[:120]
                })
    return issues


def _check_unused_import(lines, rel_path):
    issues = []
    content = "\n".join(lines)
    for i, line in enumerate(lines, 1):
        # Named imports: import { A, B } from '...'
        nm = _import_named_re.search(line)
        if nm:
            names = [n.strip().split(" as ")[-1].strip() for n in nm.group(1).split(",")]
            for name in names:
                if not name:
                    continue
                usages = len(re.findall(r'\b' + re.escape(name) + r'\b', content)) - 1
                if usages == 0:
                    issues.append({
                        "agent": AGENT_NAME, "rule_id": "DC002",
                        "rule_name": "Unused ES6 Import",
                        "severity": "info",
                        "message": f"'{name}' is imported but never used.",
                        "file": rel_path, "line": i, "snippet": line.strip()[:120]
                    })
        else:
            dm = _import_re.search(line)
            if dm and dm.group(1):
                name = dm.group(1)
                usages = len(re.findall(r'\b' + re.escape(name) + r'\b', content)) - 1
                if usages == 0:
                    issues.append({
                        "agent": AGENT_NAME, "rule_id": "DC002",
                        "rule_name": "Unused ES6 Import",
                        "severity": "info",
                        "message": f"'{name}' is imported but never used.",
                        "file": rel_path, "line": i, "snippet": line.strip()[:120]
                    })
    return issues


def _check_commented_block(lines, rel_path):
    issues = []
    consecutive = 0
    start_line = 0
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            if consecutive == 0:
                start_line = i
            consecutive += 1
        else:
            if consecutive >= 5:
                issues.append({
                    "agent": AGENT_NAME, "rule_id": "DC004",
                    "rule_name": "Large Commented-Out Code Block",
                    "severity": "info",
                    "message": f"Large block of {consecutive} consecutive comment lines. Consider removing dead code.",
                    "file": rel_path, "line": start_line, "snippet": f"({consecutive} commented lines starting here)"
                })
            consecutive = 0
    return issues


def _check_unused_variable(lines, rel_path):
    issues = []
    content = "\n".join(lines)
    for i, line in enumerate(lines, 1):
        m = _varname_re.search(line)
        if m:
            name = m.group(1)
            if name in ("module", "exports", "require", "self", "this"):
                continue
            usages = len(re.findall(r'\b' + re.escape(name) + r'\b', content)) - 1
            if usages == 0:
                issues.append({
                    "agent": AGENT_NAME, "rule_id": "DC006",
                    "rule_name": "Unused Variable",
                    "severity": "info",
                    "message": f"Variable '{name}' is declared but never used.",
                    "file": rel_path, "line": i, "snippet": line.strip()[:120]
                })
    return issues


# ── Main scan ─────────────────────────────────────────────────────────────────

def scan(abs_path, rel_path, content, lines):
    issues = []
    ext = "." + abs_path.rsplit(".", 1)[-1].lower() if "." in abs_path else ""

    for rule in RULES:
        if ext not in rule.get("extensions", set()):
            continue

        check = rule.get("check")
        if check == "unused_require":
            issues.extend(_check_unused_require(lines, rel_path))
        elif check == "unused_import":
            issues.extend(_check_unused_import(lines, rel_path))
        elif check == "commented_block":
            issues.extend(_check_commented_block(lines, rel_path))
        elif check == "unused_variable":
            issues.extend(_check_unused_variable(lines, rel_path))
        else:
            pattern = rule.get("pattern")
            if pattern:
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
