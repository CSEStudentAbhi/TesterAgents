import re

AGENT_NAME = "Code Quality"

RULES = [
    {
        "id": "CQ001",
        "name": "Empty Catch Block",
        "severity": "warning",
        "pattern": re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}', re.IGNORECASE | re.DOTALL),
        "message": "Empty catch block silently swallows errors. Add proper error handling.",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
    {
        "id": "CQ002",
        "name": "console.log Left in Code",
        "severity": "info",
        "pattern": re.compile(r'\bconsole\.(log|warn|error|debug|info)\s*\(', re.IGNORECASE),
        "message": "console.log/warn/error found. Remove debugging statements before production.",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
    {
        "id": "CQ003",
        "name": "Magic Number",
        "severity": "info",
        "pattern": re.compile(r'(?<![.\w])(?!0[xX])\b([2-9][0-9]{2,}|[1-9][0-9]{3,})\b(?!\s*[;,)\]}]?\s*\/\/)'),
        "message": "Magic number detected. Replace with a named constant for readability.",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
    {
        "id": "CQ004",
        "name": "Missing Error Handling in Async",
        "severity": "warning",
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "check": "missing_try_catch"
    },
    {
        "id": "CQ005",
        "name": "Long Function (>50 lines)",
        "severity": "info",
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "check": "long_function"
    },
    {
        "id": "CQ006",
        "name": "Deeply Nested Callbacks (Callback Hell)",
        "severity": "warning",
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "check": "callback_hell"
    },
    {
        "id": "CQ007",
        "name": "Hardcoded localhost URL",
        "severity": "warning",
        "pattern": re.compile(r'["\']https?://localhost(:\d+)?[/"\'`]', re.IGNORECASE),
        "message": "Hardcoded localhost URL found. Use environment variables for URLs.",
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".py"}
    },
    {
        "id": "CQ008",
        "name": "Synchronous File Operation",
        "severity": "info",
        "pattern": re.compile(r'\bfs\.(readFileSync|writeFileSync|existsSync|mkdirSync|unlinkSync)\s*\('),
        "message": "Synchronous fs operation blocks the event loop. Use async alternatives.",
        "extensions": {".js", ".ts"}
    },
    {
        "id": "CQ009",
        "name": "== Instead of ===",
        "severity": "info",
        "pattern": re.compile(r'(?<![=!<>])={2}(?!=)(?![=>])'),
        "message": "Use === (strict equality) instead of == to avoid type coercion bugs.",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
    {
        "id": "CQ010",
        "name": "Var Used Instead of Let/Const",
        "severity": "info",
        "pattern": re.compile(r'\bvar\s+\w+'),
        "message": "Avoid using 'var'. Use 'const' or 'let' for block scoping.",
        "extensions": {".js", ".ts", ".jsx", ".tsx"}
    },
]

# ── Helpers ──────────────────────────────────────────────────────────────────

_async_fn_re = re.compile(r'\basync\s+(function\s*\w*\s*\(|[\w]+\s*=>|\([^)]*\)\s*=>)', re.IGNORECASE)
_try_re      = re.compile(r'\btry\s*\{')
_fn_start_re = re.compile(r'(function\s*\w*\s*\(|=>|\bclass\b)', re.IGNORECASE)


def _check_missing_try_catch(lines, rel_path):
    """Flag async functions that contain await but no try/catch."""
    issues = []
    in_async = False
    fn_start = 0
    brace_depth = 0
    has_try = False
    has_await = False

    for i, line in enumerate(lines, 1):
        if _async_fn_re.search(line):
            in_async = True
            fn_start = i
            has_try = False
            has_await = False
            brace_depth = 0

        if in_async:
            brace_depth += line.count("{") - line.count("}")
            if re.search(r'\bawait\b', line):
                has_await = True
            if _try_re.search(line):
                has_try = True
            if brace_depth <= 0 and fn_start > 0:
                if has_await and not has_try:
                    issues.append({
                        "agent": AGENT_NAME, "rule_id": "CQ004",
                        "rule_name": "Missing Error Handling in Async",
                        "severity": "warning",
                        "message": "Async function uses 'await' without try/catch. Unhandled promise rejections can crash the server.",
                        "file": rel_path, "line": fn_start,
                        "snippet": lines[fn_start - 1].strip()[:120]
                    })
                in_async = False

    return issues


def _check_long_function(lines, rel_path):
    """Flag functions longer than 50 lines."""
    issues = []
    fn_start = 0
    brace_depth = 0
    in_fn = False
    fn_line_count = 0

    for i, line in enumerate(lines, 1):
        if _fn_start_re.search(line) and "{" in line:
            in_fn = True
            fn_start = i
            brace_depth = 1
            fn_line_count = 1
            continue

        if in_fn:
            brace_depth += line.count("{") - line.count("}")
            fn_line_count += 1
            if brace_depth <= 0:
                if fn_line_count > 50:
                    issues.append({
                        "agent": AGENT_NAME, "rule_id": "CQ005",
                        "rule_name": "Long Function (>50 lines)",
                        "severity": "info",
                        "message": f"Function is {fn_line_count} lines long. Consider breaking it into smaller functions.",
                        "file": rel_path, "line": fn_start,
                        "snippet": lines[fn_start - 1].strip()[:120]
                    })
                in_fn = False

    return issues


def _check_callback_hell(lines, rel_path):
    """Flag lines with indentation deeper than 6 levels suggesting callback nesting."""
    issues = []
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if indent >= 24 and re.search(r'function\s*\(|=>\s*\{', stripped):
            issues.append({
                "agent": AGENT_NAME, "rule_id": "CQ006",
                "rule_name": "Deeply Nested Callbacks",
                "severity": "warning",
                "message": "Deeply nested callback detected (callback hell). Use async/await or Promises.",
                "file": rel_path, "line": i,
                "snippet": stripped[:120]
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
        if check == "missing_try_catch":
            issues.extend(_check_missing_try_catch(lines, rel_path))
        elif check == "long_function":
            issues.extend(_check_long_function(lines, rel_path))
        elif check == "callback_hell":
            issues.extend(_check_callback_hell(lines, rel_path))
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
