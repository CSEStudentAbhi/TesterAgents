import streamlit as st
import time
import os
import sys
import pandas as pd

# Make sure scanner package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.utils.zip_extractor import extract_zip, cleanup
from scanner.agents.orchestrator import run_scan

# ─────────────────────────────────────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CodeScan — MERN Code Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────────────────
# Custom CSS — Dark Terminal Theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');

/* Global */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0d0f14;
    color: #e2e8f0;
}

/* Hide default Streamlit header/footer */
#MainMenu, footer, header { visibility: hidden; }

/* App background */
.stApp {
    background: linear-gradient(135deg, #0d0f14 0%, #111827 50%, #0d0f14 100%);
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #111827 !important;
    border-right: 1px solid #1f2937;
}

/* Title */
h1 { color: #60a5fa !important; font-family: 'Inter', sans-serif; }
h2, h3 { color: #94a3b8 !important; }

/* Terminal box */
.terminal-box {
    background: #0a0c10;
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    height: 420px;
    overflow-y: auto;
    box-shadow: 0 0 30px rgba(96, 165, 250, 0.05);
}

.terminal-line { margin: 2px 0; line-height: 1.6; }
.t-info    { color: #94a3b8; }
.t-file    { color: #60a5fa; }
.t-agent   { color: #a78bfa; }
.t-critical{ color: #f87171; font-weight: bold; }
.t-warning { color: #fbbf24; }
.t-issue-info { color: #34d399; }
.t-done    { color: #34d399; font-weight: bold; }
.t-error   { color: #f87171; }
.t-prompt  { color: #4ade80; }

/* Metric cards */
.metric-card {
    background: linear-gradient(135deg, #111827, #1a2235);
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}
.metric-card h3 { font-size: 2.2rem; margin: 4px 0; font-family: 'Inter', sans-serif; }
.metric-card p  { font-size: 0.85rem; color: #64748b; margin: 0; }

/* Issue card */
.issue-card {
    background: #111827;
    border-left: 4px solid #374151;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 8px 0;
    font-size: 0.88rem;
}
.issue-card.critical { border-left-color: #f87171; }
.issue-card.warning  { border-left-color: #fbbf24; }
.issue-card.info     { border-left-color: #34d399; }

.issue-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.badge {
    display: inline-block; padding: 2px 10px;
    border-radius: 20px; font-size: 0.75rem; font-weight: 600;
}
.badge-critical { background: rgba(248,113,113,0.15); color: #f87171; border: 1px solid rgba(248,113,113,0.3); }
.badge-warning  { background: rgba(251,191,36,0.15);  color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }
.badge-info     { background: rgba(52,211,153,0.15);  color: #34d399; border: 1px solid rgba(52,211,153,0.3); }
.badge-agent    { background: rgba(167,139,250,0.15); color: #a78bfa; border: 1px solid rgba(167,139,250,0.3); }

.issue-snippet {
    background: #0a0c10;
    border-radius: 6px;
    padding: 8px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #94a3b8;
    margin-top: 8px;
    overflow-x: auto;
    white-space: pre;
}

/* Upload zone */
[data-testid="stFileUploader"] {
    background: #111827;
    border: 2px dashed #1e3a5f;
    border-radius: 12px;
    padding: 20px;
}

/* Progress bar */
.stProgress > div > div { background: linear-gradient(90deg, #3b82f6, #8b5cf6) !important; }

/* Buttons */
.stButton button {
    background: linear-gradient(135deg, #3b82f6, #8b5cf6) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 10px 24px !important;
    font-weight: 600 !important;
    transition: all 0.2s !important;
}
.stButton button:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(59,130,246,0.4) !important; }

/* Tabs */
.stTabs [data-baseweb="tab"] { color: #64748b !important; }
.stTabs [aria-selected="true"] { color: #60a5fa !important; border-bottom-color: #60a5fa !important; }

/* Selectbox */
.stSelectbox > div > div { background: #111827 !important; border-color: #1f2937 !important; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #111827; }
::-webkit-scrollbar-thumb { background: #374151; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_EMOJI = {"critical": "🔴", "warning": "🟡", "info": "🟢"}
AGENT_EMOJI    = {"Security": "🛡️", "Dead Code": "💀", "Code Quality": "⚡", "Dependency": "📦", "Structure": "🏗️"}

def severity_color_class(sev):
    return {"critical": "critical", "warning": "warning", "info": "info"}.get(sev, "info")

def render_issue_card(issue):
    sev   = issue.get("severity", "info")
    agent = issue.get("agent", "")
    st.markdown(f"""
    <div class="issue-card {sev}">
        <div class="issue-header">
            <span class="badge badge-{sev}">{SEVERITY_EMOJI.get(sev,'')} {sev.upper()}</span>
            <span class="badge badge-agent">{AGENT_EMOJI.get(agent,'🤖')} {agent}</span>
            <strong style="color:#e2e8f0">{issue.get('rule_name','')}</strong>
            <span style="color:#4b5563; font-size:0.8rem">({issue.get('rule_id','')})</span>
        </div>
        <div style="color:#94a3b8; margin-bottom:6px">{issue.get('message','')}</div>
        <div style="color:#4b5563; font-size:0.8rem">
            📁 <span style="color:#60a5fa">{issue.get('file','')}</span>
            &nbsp;·&nbsp; Line <strong style="color:#a78bfa">{issue.get('line','?')}</strong>
        </div>
        {"<div class='issue-snippet'>" + issue.get('snippet','') + "</div>" if issue.get('snippet') else ""}
    </div>
    """, unsafe_allow_html=True)

def render_terminal_line(html_class, text):
    return f'<div class="terminal-line {html_class}">{text}</div>'

def build_terminal_html(lines_html):
    inner = "\n".join(lines_html)
    return f"""
    <div class="terminal-box" id="terminal-scroll">
        {inner}
        <script>
            var el = document.getElementById('terminal-scroll');
            if(el) el.scrollTop = el.scrollHeight;
        </script>
    </div>
    """

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 CodeScan")
    st.markdown("<div style='color:#64748b; font-size:0.85rem'>Rule-based static analysis for MERN projects</div>", unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("### 🤖 Active Agents")
    st.markdown("""
    <div style='font-size:0.85rem; color:#94a3b8; line-height:2'>
    🏗️ <b>Structure</b> — 12 rules<br>
    🛡️ <b>Security</b> — 12 rules<br>
    💀 <b>Dead Code</b> — 6 rules<br>
    ⚡ <b>Code Quality</b> — 10 rules<br>
    📦 <b>Dependency</b> — 5 rules<br>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("### 📋 Severity Guide")
    st.markdown("""
    <div style='font-size:0.82rem; line-height:2'>
    🔴 <b style='color:#f87171'>Critical</b> — Security / crash risk<br>
    🟡 <b style='color:#fbbf24'>Warning</b> — Bad practice<br>
    🟢 <b style='color:#34d399'>Info</b> — Code quality tip
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("<div style='color:#374151; font-size:0.75rem'>Scans .js .ts .jsx .tsx .json .env files<br>Skips node_modules, dist, build</div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Main App
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("# 🔍 CodeScan — MERN Static Analyzer")
st.markdown("<div style='color:#64748b; margin-bottom:24px'>Upload your MERN project as a ZIP file. All agents will scan your code live.</div>", unsafe_allow_html=True)

# Session state
if "scan_done" not in st.session_state:
    st.session_state.scan_done = False
if "issues" not in st.session_state:
    st.session_state.issues = []
if "scan_stats" not in st.session_state:
    st.session_state.scan_stats = {}

# ── Upload Section ─────────────────────────────────────────────────────────────
if not st.session_state.scan_done:
    st.markdown("### 📁 Upload Your Project")
    uploaded = st.file_uploader(
        "Drop your MERN project ZIP here",
        type=["zip"],
        help="Zip your entire project folder (node_modules will be skipped automatically)"
    )

    if uploaded:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.success(f"✅ **{uploaded.name}** uploaded — {uploaded.size // 1024} KB")
        with col2:
            start_btn = st.button("🚀 Start Scan", use_container_width=True)

        if start_btn:
            st.markdown("---")
            st.markdown("### ⚡ Live Scan Terminal")

            # Progress + terminal placeholders
            progress_bar  = st.progress(0, text="Initializing...")
            terminal_ph   = st.empty()
            status_ph     = st.empty()

            terminal_lines = [
                render_terminal_line("t-prompt", "$ codescan --agents=all --live"),
                render_terminal_line("t-info",   "  Extracting project files..."),
            ]
            terminal_ph.markdown(build_terminal_html(terminal_lines), unsafe_allow_html=True)

            # Extract zip
            try:
                extract_dir, tmp_dir = extract_zip(uploaded)
            except Exception as e:
                st.error(f"❌ Failed to extract ZIP: {e}")
                st.stop()

            issues_collected = []
            # Use a mutable dict so nested on_event can mutate without nonlocal
            state = {"total_files": 0, "current_file": "", "current_agent": ""}

            def on_event(ev):

                etype = ev.get("type")

                if etype == "scan:start":
                    state["total_files"] = ev["total_files"]
                    terminal_lines.append(render_terminal_line("t-info", f"  Found <b>{state['total_files']}</b> files to scan"))
                    terminal_lines.append(render_terminal_line("t-info", "  ─────────────────────────────────────"))

                elif etype == "scan:file":
                    state["current_file"] = ev["file"]
                    idx          = ev["index"]
                    total_files  = state["total_files"]
                    pct          = int((idx / max(total_files, 1)) * 100)
                    progress_bar.progress(pct / 100, text=f"Scanning {idx}/{total_files}: {state['current_file']}")
                    terminal_lines.append(
                        render_terminal_line("t-file", f"  📄 [{idx}/{total_files}] {state['current_file']}")
                    )

                elif etype == "scan:agent":
                    state["current_agent"] = ev["agent"]
                    emoji = AGENT_EMOJI.get(state["current_agent"], "🤖")
                    terminal_lines.append(
                        render_terminal_line("t-agent", f"     {emoji} Running {state['current_agent']} Agent...")
                    )

                elif etype == "scan:issue":
                    issue = ev["issue"]
                    issues_collected.append(issue)
                    sev   = issue.get("severity", "info")
                    rid   = issue.get("rule_id", "")
                    name  = issue.get("rule_name", "")
                    line  = issue.get("line", "?")
                    cls   = {"critical": "t-critical", "warning": "t-warning", "info": "t-issue-info"}.get(sev, "t-issue-info")
                    emoji = SEVERITY_EMOJI.get(sev, "")
                    terminal_lines.append(
                        render_terminal_line(cls, f"       {emoji} [{rid}] {name} — Line {line}")
                    )

                elif etype == "scan:done":
                    progress_bar.progress(1.0, text="✅ Scan complete!")
                    terminal_lines.append(render_terminal_line("t-info", "  ─────────────────────────────────────"))
                    terminal_lines.append(
                        render_terminal_line("t-done", f"  ✅ Scan complete! Found <b>{ev['total_issues']}</b> issues.")
                    )

                elif etype == "scan:error":
                    terminal_lines.append(
                        render_terminal_line("t-error", f"  ⚠ Could not read: {ev['file']}")
                    )

                # Keep only last 80 terminal lines for performance
                if len(terminal_lines) > 80:
                    terminal_lines.pop(2)

                terminal_ph.markdown(build_terminal_html(terminal_lines), unsafe_allow_html=True)

            # Run scan
            with st.spinner(""):
                all_issues = run_scan(extract_dir, on_event)

            cleanup(tmp_dir)

            # Save to session
            st.session_state.issues = all_issues
            st.session_state.scan_done = True
            st.session_state.scan_stats = {
                "total": len(all_issues),
                "critical": sum(1 for i in all_issues if i["severity"] == "critical"),
                "warning":  sum(1 for i in all_issues if i["severity"] == "warning"),
                "info":     sum(1 for i in all_issues if i["severity"] == "info"),
                "project":  uploaded.name,
            }

            time.sleep(0.5)
            st.rerun()

# ── Results Section ────────────────────────────────────────────────────────────
else:
    issues = st.session_state.issues
    stats  = st.session_state.scan_stats

    # Header
    col_h1, col_h2 = st.columns([4, 1])
    with col_h1:
        st.markdown(f"### 📊 Scan Results — `{stats.get('project','')}`")
    with col_h2:
        if st.button("🔄 New Scan"):
            st.session_state.scan_done = False
            st.session_state.issues    = []
            st.session_state.scan_stats = {}
            st.rerun()

    # Stats row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""<div class="metric-card">
            <p>Total Issues</p><h3 style="color:#60a5fa">{stats.get('total',0)}</h3>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class="metric-card">
            <p>🔴 Critical</p><h3 style="color:#f87171">{stats.get('critical',0)}</h3>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class="metric-card">
            <p>🟡 Warning</p><h3 style="color:#fbbf24">{stats.get('warning',0)}</h3>
        </div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class="metric-card">
            <p>🟢 Info</p><h3 style="color:#34d399">{stats.get('info',0)}</h3>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if not issues:
        st.success("🎉 No issues found! Your code looks clean.")
    else:
        tab1, tab2, tab3 = st.tabs(["🔍 All Issues", "📂 By File", "📈 Summary"])

        # ── Tab 1: All Issues ──────────────────────────────────────────────────
        with tab1:
            col_f1, col_f2, col_f3 = st.columns(3)
            with col_f1:
                sev_filter = st.selectbox("Filter by Severity", ["All", "critical", "warning", "info"])
            with col_f2:
                agents = ["All"] + list({i["agent"] for i in issues})
                agent_filter = st.selectbox("Filter by Agent", agents)
            with col_f3:
                files = ["All"] + sorted({i["file"] for i in issues})
                file_filter = st.selectbox("Filter by File", files)

            filtered = [
                i for i in issues
                if (sev_filter   == "All" or i["severity"] == sev_filter)
                and (agent_filter == "All" or i["agent"]    == agent_filter)
                and (file_filter  == "All" or i["file"]     == file_filter)
            ]

            st.markdown(f"<div style='color:#64748b; font-size:0.85rem; margin-bottom:12px'>Showing {len(filtered)} of {len(issues)} issues</div>", unsafe_allow_html=True)

            # Show critical first
            for sev in ["critical", "warning", "info"]:
                sev_issues = [i for i in filtered if i["severity"] == sev]
                if sev_issues:
                    st.markdown(f"#### {SEVERITY_EMOJI[sev]} {sev.capitalize()} ({len(sev_issues)})")
                    for issue in sev_issues:
                        render_issue_card(issue)

        # ── Tab 2: By File ─────────────────────────────────────────────────────
        with tab2:
            file_map = {}
            for issue in issues:
                file_map.setdefault(issue["file"], []).append(issue)

            for filepath, file_issues in sorted(file_map.items(), key=lambda x: -len(x[1])):
                crit  = sum(1 for i in file_issues if i["severity"] == "critical")
                warns = sum(1 for i in file_issues if i["severity"] == "warning")
                infos = sum(1 for i in file_issues if i["severity"] == "info")
                label = f"📄 `{filepath}` — 🔴{crit} 🟡{warns} 🟢{infos}"
                with st.expander(label):
                    for issue in file_issues:
                        render_issue_card(issue)

        # ── Tab 3: Summary ─────────────────────────────────────────────────────
        with tab3:
            # By agent
            st.markdown("#### Issues by Agent")
            agent_data = {}
            for issue in issues:
                a = issue["agent"]
                agent_data[a] = agent_data.get(a, 0) + 1

            df_agent = pd.DataFrame(list(agent_data.items()), columns=["Agent", "Issues"])
            st.bar_chart(df_agent.set_index("Agent"))

            st.markdown("#### Issues by Severity")
            sev_data = {"Critical": stats["critical"], "Warning": stats["warning"], "Info": stats["info"]}
            df_sev = pd.DataFrame(list(sev_data.items()), columns=["Severity", "Count"])
            st.bar_chart(df_sev.set_index("Severity"))

            # Top files
            st.markdown("#### Top 10 Files by Issue Count")
            file_counts = {}
            for issue in issues:
                file_counts[issue["file"]] = file_counts.get(issue["file"], 0) + 1
            top_files = sorted(file_counts.items(), key=lambda x: -x[1])[:10]
            df_files = pd.DataFrame(top_files, columns=["File", "Issues"])
            st.dataframe(df_files, use_container_width=True, hide_index=True)
