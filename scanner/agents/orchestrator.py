"""
Agent Orchestrator — runs all agents and collects results.
1. Structure agent runs ONCE on the whole project root.
2. File-level agents run on every scannable file.
"""

from scanner.agents import security_agent, dead_code_agent, code_quality_agent, dependency_agent
from scanner.agents import structure_agent
from scanner.utils.file_walker import walk_files

FILE_AGENTS = [
    security_agent,
    dead_code_agent,
    code_quality_agent,
    dependency_agent,
]


def run_scan(project_dir, on_event):
    """
    Walk project files and run all agents.

    Args:
        project_dir: Root directory of extracted project
        on_event:    Callback fn(event_dict) called for each live event

    Returns:
        list of all issue dicts
    """
    files = walk_files(project_dir)
    total = len(files)
    all_issues = []

    on_event({"type": "scan:start", "total_files": total})

    # ── Phase 1: Structure Analysis (whole project) ───────────────────────────
    on_event({"type": "scan:agent", "agent": structure_agent.AGENT_NAME, "file": "project root"})
    try:
        struct_issues = structure_agent.scan_project(project_dir)
        for issue in struct_issues:
            all_issues.append(issue)
            on_event({"type": "scan:issue", "issue": issue})
    except Exception as e:
        on_event({"type": "scan:agent_error", "agent": structure_agent.AGENT_NAME, "error": str(e)})

    # ── Phase 2: File-by-file analysis ───────────────────────────────────────
    for idx, (abs_path, rel_path) in enumerate(files, start=1):
        on_event({
            "type": "scan:file",
            "file": rel_path,
            "index": idx,
            "total": total
        })

        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()
        except Exception as e:
            on_event({"type": "scan:error", "file": rel_path, "error": str(e)})
            continue

        for agent in FILE_AGENTS:
            on_event({"type": "scan:agent", "agent": agent.AGENT_NAME, "file": rel_path})
            try:
                issues = agent.scan(abs_path, rel_path, content, lines)
                for issue in issues:
                    all_issues.append(issue)
                    on_event({"type": "scan:issue", "issue": issue})
            except Exception as e:
                on_event({"type": "scan:agent_error", "agent": agent.AGENT_NAME, "error": str(e)})

    on_event({"type": "scan:done", "total_issues": len(all_issues)})
    return all_issues
