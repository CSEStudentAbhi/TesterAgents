"""
Structure Agent — Analyzes overall MERN project folder structure.
Unlike other agents this runs once on the whole project root,
not file-by-file.
"""

import os
import json

AGENT_NAME = "Structure"

# Dirs to skip when walking
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", "coverage", ".cache"}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_all_dirs_and_files(root):
    """Return sets of all relative directory paths and filenames."""
    all_dirs  = set()
    all_files = {}  # rel_path -> abs_path

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")

        for d in dirnames:
            all_dirs.add(os.path.join(rel_dir, d).replace("\\", "/").lstrip("./"))

        for f in filenames:
            rel_file = os.path.join(rel_dir, f).replace("\\", "/").lstrip("./")
            all_files[rel_file] = os.path.join(dirpath, f)

    return all_dirs, all_files


def _has_dir(all_dirs, name):
    """Check if any directory in the project contains 'name'."""
    return any(
        part == name
        for d in all_dirs
        for part in d.split("/")
    )


def _detect_project_type(all_files):
    """Detect if a folder is express backend, react frontend, or both."""
    results = []
    for rel_path, abs_path in all_files.items():
        if rel_path.endswith("package.json") and rel_path.count("/") <= 1:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    pkg = json.load(f)
                deps = {}
                deps.update(pkg.get("dependencies", {}))
                deps.update(pkg.get("devDependencies", {}))
                dep_names = [k.lower() for k in deps]
                is_react   = "react" in dep_names
                is_express = "express" in dep_names
                results.append({
                    "path": rel_path,
                    "name": pkg.get("name", rel_path),
                    "is_react": is_react,
                    "is_express": is_express,
                    "deps": dep_names
                })
            except Exception:
                pass
    return results


def _get_entry_files(all_files):
    """Find common entry files."""
    entry_names = {"index.js", "server.js", "app.js", "main.js", "index.ts", "server.ts"}
    return {rel: abs_p for rel, abs_p in all_files.items()
            if os.path.basename(rel) in entry_names}


def _count_lines(abs_path):
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _file_contains(abs_path, *patterns):
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return all(p.lower() in content.lower() for p in patterns)
    except Exception:
        return False


# ── Checks ────────────────────────────────────────────────────────────────────

def _check_backend_structure(all_dirs, all_files, issues):
    """Check Express/Node backend folder conventions."""
    REQUIRED_BACKEND_DIRS = {
        "routes":      ("STR001", "Missing 'routes/' Folder",
                        "No 'routes/' folder found. Route definitions should be separated from the server entry file."),
        "controllers": ("STR002", "Missing 'controllers/' Folder",
                        "No 'controllers/' folder found. Business logic should be in controllers, not directly in routes."),
        "models":      ("STR003", "Missing 'models/' Folder",
                        "No 'models/' folder found. Database schemas/models should live in a dedicated models/ directory."),
        "middleware":  ("STR004", "Missing 'middleware/' Folder",
                        "No 'middleware/' folder found. Auth, validation, and error middleware should be in a middleware/ directory."),
        "config":      ("STR005", "Missing 'config/' Folder",
                        "No 'config/' folder found. DB connection, constants, and configuration should be in config/."),
    }

    for folder, (rule_id, rule_name, message) in REQUIRED_BACKEND_DIRS.items():
        if not _has_dir(all_dirs, folder):
            issues.append({
                "agent": AGENT_NAME,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": "warning",
                "message": message,
                "file": "project root",
                "line": 0,
                "snippet": f"Expected folder: {folder}/"
            })


def _check_frontend_structure(all_dirs, all_files, issues):
    """Check React frontend folder conventions."""
    REQUIRED_FRONTEND_DIRS = {
        "components": ("STR006", "Missing 'components/' Folder",
                       "No 'components/' folder found. Reusable UI components should be in a components/ directory."),
        "pages":      ("STR007", "Missing 'pages/' or 'views/' Folder",
                       "No 'pages/' or 'views/' folder found. Page-level components should be organized in pages/."),
    }

    for folder, (rule_id, rule_name, message) in REQUIRED_FRONTEND_DIRS.items():
        if folder == "pages" and _has_dir(all_dirs, "views"):
            continue  # views/ is acceptable too
        if not _has_dir(all_dirs, folder):
            issues.append({
                "agent": AGENT_NAME,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": "info",
                "message": message,
                "file": "project root",
                "line": 0,
                "snippet": f"Expected folder: {folder}/"
            })


def _check_oversized_entry_file(all_files, issues):
    """Flag server entry files that are too large (routes mixed with server setup)."""
    entry_files = _get_entry_files(all_files)
    for rel, abs_p in entry_files.items():
        lines = _count_lines(abs_p)
        if lines > 80:
            # Check if it contains route definitions
            if _file_contains(abs_p, "router.get", "app.get", "app.post", "router.post"):
                issues.append({
                    "agent": AGENT_NAME,
                    "rule_id": "STR008",
                    "rule_name": "Routes Mixed Into Entry File",
                    "severity": "warning",
                    "message": (
                        f"Entry file '{os.path.basename(rel)}' is {lines} lines long and contains route definitions. "
                        "Extract routes to a routes/ folder and controllers to a controllers/ folder."
                    ),
                    "file": rel,
                    "line": 1,
                    "snippet": f"{lines} lines — routes mixed with server setup"
                })


def _check_missing_gitignore(all_files, issues):
    """Check for missing .gitignore."""
    has_gitignore = any(".gitignore" in f for f in all_files)
    if not has_gitignore:
        issues.append({
            "agent": AGENT_NAME,
            "rule_id": "STR009",
            "rule_name": "Missing .gitignore File",
            "severity": "warning",
            "message": "No .gitignore found. node_modules, .env, and build artifacts may be committed to git.",
            "file": "project root",
            "line": 0,
            "snippet": "Add a .gitignore with: node_modules/, .env, dist/, build/"
        })


def _check_missing_env_example(all_files, issues):
    """Check for missing .env.example."""
    has_env_example = any(".env.example" in f or ".env.sample" in f for f in all_files)
    has_env         = any(f.endswith(".env") or "/.env" in f for f in all_files)
    if has_env and not has_env_example:
        issues.append({
            "agent": AGENT_NAME,
            "rule_id": "STR010",
            "rule_name": "Missing .env.example File",
            "severity": "info",
            "message": ".env file exists but no .env.example found. Provide .env.example so other developers know which variables are needed.",
            "file": "project root",
            "line": 0,
            "snippet": "Create .env.example with placeholder values (no real secrets)"
        })


def _check_missing_readme(all_files, issues):
    """Check for missing README."""
    has_readme = any("readme" in f.lower() for f in all_files)
    if not has_readme:
        issues.append({
            "agent": AGENT_NAME,
            "rule_id": "STR011",
            "rule_name": "Missing README.md",
            "severity": "info",
            "message": "No README.md found. Every project should have documentation explaining setup and usage.",
            "file": "project root",
            "line": 0,
            "snippet": "Add README.md with: project description, setup steps, env variables, API docs"
        })


def _check_monolith_pattern(all_dirs, all_files, issues):
    """Detect if backend is a monolith (everything in one file, no structure)."""
    js_files = [f for f in all_files if f.endswith((".js", ".ts")) and "node_modules" not in f]
    # If fewer than 3 JS files and no routes/controllers/models
    if len(js_files) < 3 and not (_has_dir(all_dirs, "routes") or _has_dir(all_dirs, "controllers")):
        if len(js_files) > 0:
            issues.append({
                "agent": AGENT_NAME,
                "rule_id": "STR012",
                "rule_name": "Monolithic Structure Detected",
                "severity": "warning",
                "message": (
                    f"Only {len(js_files)} JS/TS file(s) found with no route/controller separation. "
                    "The entire application appears to be in a single file. This is not scalable. "
                    "Split into routes/, controllers/, models/, middleware/."
                ),
                "file": js_files[0] if js_files else "project root",
                "line": 1,
                "snippet": "Refactor into: routes/ controllers/ models/ middleware/ config/"
            })


# ── Main entry ────────────────────────────────────────────────────────────────

def scan_project(project_root):
    """
    Analyze the overall project structure.
    Returns a list of issue dicts.
    """
    issues = []
    all_dirs, all_files = _get_all_dirs_and_files(project_root)
    project_types = _detect_project_type(all_files)

    has_backend  = any(p["is_express"] for p in project_types)
    has_frontend = any(p["is_react"]   for p in project_types)

    # If we can't detect types, assume it might be a backend
    if not project_types:
        has_backend = True

    if has_backend:
        _check_backend_structure(all_dirs, all_files, issues)
        _check_oversized_entry_file(all_files, issues)
        _check_monolith_pattern(all_dirs, all_files, issues)

    if has_frontend:
        _check_frontend_structure(all_dirs, all_files, issues)

    # Always check
    _check_missing_gitignore(all_files, issues)
    _check_missing_env_example(all_files, issues)
    _check_missing_readme(all_files, issues)

    return issues
