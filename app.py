import os
from datetime import datetime
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st
from pyswip import Prolog

from ids_search import iterative_deepening_search
from pathfinder import a_star_search, build_network_graph, uniform_cost_search
from sandbox_setup import build_bank_sandbox

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AEGIS | AI Digital Forensics Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- CUSTOM SOC STYLING ---
st.markdown(
    """
    <style>
    /* Main header banner */
    .soc-banner {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 60%, #0D3B4C 100%);
        border: 1px solid #1E293B;
        border-left: 5px solid #00F5D4;
        padding: 1.4rem 1.8rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
    }
    .soc-banner h1 {
        color: #F8FAFC;
        font-size: 1.85rem;
        margin: 0 0 0.35rem 0;
        letter-spacing: 0.3px;
    }
    .soc-banner p {
        color: #94A3B8;
        font-size: 0.95rem;
        margin: 0;
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background-color: #131C31;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    }
    div[data-testid="stMetric"] label {
        color: #94A3B8 !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #00F5D4 !important;
        font-size: 1.5rem !important;
        font-weight: 700;
    }

    /* Alert & Verdict Cards */
    .verdict-critical {
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.16) 0%, rgba(19, 28, 49, 0.95) 100%);
        border: 1px solid rgba(239, 68, 68, 0.45);
        border-left: 5px solid #EF4444;
        padding: 1.1rem 1.4rem;
        border-radius: 10px;
        margin-bottom: 1rem;
    }
    .rule-card {
        background-color: #131C31;
        border: 1px solid #1E293B;
        border-left: 4px solid #F59E0B;
        padding: 0.85rem 1.1rem;
        border-radius: 8px;
        margin-bottom: 0.65rem;
    }
    .badge-critical {
        background-color: #EF4444;
        color: #FFFFFF;
        padding: 0.2rem 0.6rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
    .badge-ok {
        background-color: #10B981;
        color: #06281E;
        padding: 0.2rem 0.6rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Ensure sandbox exists
if not os.path.exists("bank_server"):
    build_bank_sandbox()

# --- HEADER BANNER ---
st.markdown(
    """
    <div class="soc-banner">
        <h1>🛡️ AEGIS — Autonomous Digital Forensics & Intrusion Investigation Agent</h1>
        <p>Hybrid AI Pipeline: Iterative Deepening Log Crawler • Informed Graph Pathfinding (UCS / A*) • SWI-Prolog Symbolic Policy Engine</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.markdown("### ⚙️ Investigation Parameters")
    algorithm = st.selectbox(
        "Path Reconstruction Strategy",
        ["A* Search (Heuristic-Guided)", "Uniform Cost Search (UCS)"],
    )
    max_depth = st.slider(
        "IDS Directory Depth Ceiling", min_value=1, max_value=10, value=6
    )

    st.divider()
    run_btn = st.button(
        "🚀 Launch Forensic Sweep", type="primary", use_container_width=True
    )
    if st.button("🔄 Rebuild Bank Sandbox", use_container_width=True):
        build_bank_sandbox()
        st.toast("Bank server sandbox regenerated!", icon="✅")

    st.divider()
    st.markdown(
        """
        **System Architecture**
        - **Crawler:** Depth-Limited IDS
        - **Topology:** `NetworkX` Weighted DiGraph
        - **Reasoner:** `SWI-Prolog 11.0` (`pyswip`)
        """
    )

if not run_btn:
    st.info(
        "👈 Configure your search parameters in the sidebar and click **Launch Forensic Sweep** to begin the autonomous investigation."
    )
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("#### 1️⃣ Deep Log Crawling")
        st.caption(
            "Iteratively sweeps nested server directories from Depth 0 to N to uncover tampered audit trails without exhausting memory."
        )
    with c2:
        st.markdown("#### 2️⃣ Lateral Movement Mapping")
        st.caption(
            "Compares Uniform Cost Search and A* heuristics to reconstruct the attacker's least-cost path across network nodes."
        )
    with c3:
        st.markdown("#### 3️⃣ Symbolic Policy Verification")
        st.caption(
            "Evaluates extracted log evidence against formal Prolog access-control rules to produce explainable breach verdicts."
        )
    st.stop()

# --- RUN INVESTIGATION PIPELINE ---
with st.spinner("Executing IDS sweep, graph pathfinding, and Prolog inference..."):
    ids_result = iterative_deepening_search("bank_server", max_limit=max_depth)

    if not ids_result:
        st.warning("No tampered audit logs were found within the selected depth limit.")
        st.stop()

    found_path, evidence_df = ids_result

    # Run SWI-Prolog Engine
    prolog = Prolog()
    rules_path = os.path.abspath("forensics_rules.pl").replace("\\", "/")
    prolog.consult(rules_path)
    list(prolog.query("reset_kb"))

    perms_df = pd.read_csv("bank_server/permissions.csv")
    for _, row in perms_df.iterrows():
        prolog.assertz(f"permitted('{row['user']}', '{row['allowed_target']}')")

    for _, row in evidence_df.iterrows():
        prolog.assertz(
            f"log_event('{row['timestamp']}', '{row['user']}', "
            f"'{row['target']}', '{row['action']}', '{row['status']}')"
        )

    breaches = list(prolog.query("critical_breach(User, Target)"))
    unauth_hits = list(prolog.query("unauthorized_access(User, Target)"))
    tamper_hits = list(prolog.query("log_tampered(User, Target)"))
    exfil_hits = list(prolog.query("suspicious_exfiltration(User, Target)"))

    # Run Graph Pathfinding
    G, heuristics = build_network_graph()
    ucs_path, ucs_cost, ucs_expanded = uniform_cost_search(
        G, "public_portal", "credit_cards_db"
    )
    astar_path, astar_cost, astar_expanded = a_star_search(
        G, heuristics, "public_portal", "credit_cards_db"
    )

    if "A*" in algorithm:
        active_path, active_cost, active_expanded = (
            astar_path,
            astar_cost,
            astar_expanded,
        )
    else:
        active_path, active_cost, active_expanded = ucs_path, ucs_cost, ucs_expanded

# --- TOP KPI SUMMARY ROW ---
suspect_user = evidence_df.iloc[0]["user"]
target_asset = evidence_df.iloc[0]["target"]

k1, k2, k3, k4 = st.columns(4)
k1.metric("Threat Severity", "CRITICAL" if breaches else "LOW")
k2.metric("Primary Suspect", suspect_user)
k3.metric("Compromised Asset", target_asset)
k4.metric("Attack Path Cost", f"{active_cost} Hops/Units")

st.markdown("<br>", unsafe_allow_html=True)

# --- STRUCTURED TABS ---
tab1, tab2, tab3 = st.tabs(
    [
        "🔍 1. IDS Evidence & Permissions",
        "🕸️ 2. Attack Path Topology",
        "⚖️ 3. Prolog Verdict & Incident Report",
    ]
)

# === TAB 1: IDS EVIDENCE ===
with tab1:
    left, right = st.columns([1.3, 1])
    with left:
        st.subheader("Tampered Log Artifact Located")
        st.code(found_path, language="text")
        st.dataframe(evidence_df, use_container_width=True, hide_index=True)

    with right:
        st.subheader("Access Control Matrix (`permissions.csv`)")
        st.dataframe(perms_df, use_container_width=True, hide_index=True)
        st.caption(
            "Prolog cross-references the extracted suspect (`user_a`) against this whitelist to prove unauthorized privilege escalation."
        )

# === TAB 2: NETWORK ATTACK GRAPH ===
with tab2:
    g_col, stats_col = st.columns([2.2, 1])

    with g_col:
        st.subheader(f"Lateral Movement Graph ({algorithm})")
        fig, ax = plt.subplots(figsize=(10, 5.2))
        fig.patch.set_facecolor("#0B1120")
        ax.set_facecolor("#0B1120")

        # Structured layered coordinates for clean presentation
        pos = {
            "public_portal": (0, 1),
            "dmz_gateway": (1.5, 1.7),
            "web_proxy": (1.5, 0.3),
            "app_server": (3.2, 1),
            "internal_auth": (4.8, 1.7),
            "core_db": (6.3, 1),
            "credit_cards_db": (8.0, 1),
        }

        path_edges = list(zip(active_path, active_path[1:]))

        node_colors = []
        for n in G.nodes():
            if n == active_path[0]:
                node_colors.append("#F59E0B")  # Entry point
            elif n == active_path[-1]:
                node_colors.append("#EF4444")  # Target compromised DB
            elif n in active_path:
                node_colors.append("#EC4899")  # Compromised pivot node
            else:
                node_colors.append("#1E293B")  # Uncompromised node

        edge_colors = [
            "#00F5D4" if e in path_edges else "#334155" for e in G.edges()
        ]
        edge_widths = [3.2 if e in path_edges else 1.3 for e in G.edges()]

        nx.draw_networkx_nodes(
            G,
            pos,
            ax=ax,
            node_color=node_colors,
            node_size=2600,
            edgecolors="#94A3B8",
            linewidths=1.5,
        )
        nx.draw_networkx_labels(
            G,
            pos,
            ax=ax,
            font_size=8,
            font_weight="bold",
            font_color="#F8FAFC",
        )
        nx.draw_networkx_edges(
            G,
            pos,
            ax=ax,
            edge_color=edge_colors,
            width=edge_widths,
            arrows=True,
            arrowsize=20,
            connectionstyle="arc3,rad=0.05",
        )
        edge_labels = nx.get_edge_attributes(G, "weight")
        nx.draw_networkx_edge_labels(
            G,
            pos,
            edge_labels=edge_labels,
            ax=ax,
            font_size=8,
            font_color="#00F5D4",
            bbox=dict(boxstyle="round,pad=0.2", fc="#131C31", ec="#334155"),
        )

        legend_items = [
            mpatches.Patch(color="#F59E0B", label="Entry Point"),
            mpatches.Patch(color="#EC4899", label="Compromised Pivot"),
            mpatches.Patch(color="#EF4444", label="Target Asset"),
            mpatches.Patch(color="#1E293B", label="Clean Node"),
        ]
        ax.legend(
            handles=legend_items,
            loc="lower left",
            facecolor="#131C31",
            edgecolor="#334155",
            labelcolor="#E2E8F0",
            fontsize=8,
        )
        ax.axis("off")
        st.pyplot(fig)

    with stats_col:
        st.subheader("Algorithm Efficiency")
        comp_df = pd.DataFrame(
            [
                {
                    "Algorithm": "Uniform Cost (UCS)",
                    "Total Cost": ucs_cost,
                    "Nodes Expanded": ucs_expanded,
                },
                {
                    "Algorithm": "A* Search",
                    "Total Cost": astar_cost,
                    "Nodes Expanded": astar_expanded,
                },
            ]
        )
        st.dataframe(comp_df, use_container_width=True, hide_index=True)

        st.markdown("**Reconstructed Attack Chain:**")
        for idx, hop in enumerate(active_path, 1):
            st.markdown(f"`Step {idx}` $\\rightarrow$ **{hop}**")

# === TAB 3: SYMBOLIC VERDICT & REPORT ===
with tab3:
    v_col, action_col = st.columns([1.4, 1])

    with v_col:
        st.subheader("Formal Symbolic Reasoning Trace")
        if breaches:
            st.markdown(
                f"""
                <div class="verdict-critical">
                    <span class="badge-critical">CRITICAL BREACH CONFIRMED</span>
                    <h4 style="color:#F8FAFC; margin:0.6rem 0 0.3rem 0;">
                        Subject <code>{suspect_user}</code> compromised <code>{target_asset}</code>
                    </h4>
                    <p style="color:#CBD5E1; margin:0; font-size:0.9rem;">
                        All three forensic violation predicates evaluated to <b>TRUE</b> inside SWI-Prolog.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        rules_status = [
            (
                "unauthorized_access(User, Target)",
                bool(unauth_hits),
                "Subject executed operations without matching clearance in permissions.csv.",
            ),
            (
                "log_tampered(User, Target)",
                bool(tamper_hits),
                "Log status flag matches TAMPERED_LOG integrity violation.",
            ),
            (
                "suspicious_exfiltration(User, Target)",
                bool(exfil_hits),
                "High-risk EXPORT command executed during off-hours window (02:00 AM).",
            ),
        ]

        for rule_name, fired, desc in rules_status:
            badge = (
                '<span class="badge-critical">TRIGGERED</span>'
                if fired
                else '<span class="badge-ok">PASSED</span>'
            )
            st.markdown(
                f"""
                <div class="rule-card">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <code style="color:#00F5D4; font-size:0.9rem;">{rule_name}</code>
                        {badge}
                    </div>
                    <p style="color:#94A3B8; margin:0.4rem 0 0 0; font-size:0.85rem;">{desc}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with action_col:
        st.subheader("Containment & Export")
        st.markdown(
            """
            **Recommended SOC Containment:**
            1. Revoke session tokens & credentials for **`user_a`**.
            2. Isolate **`credit_cards_db`** and rotate database encryption keys.
            3. Patch lateral-movement pivot across **`dmz_gateway`** $\\rightarrow$ **`app_server`**.
            """
        )

        report_text = f"""AEGIS DIGITAL FORENSICS INCIDENT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
====================================================
1. EVIDENCE DISCOVERY (IDS CRAWLER)
   - Artifact Path : {found_path}
   - Suspect User  : {suspect_user}
   - Target Asset  : {target_asset}
   - Action/Status : {evidence_df.iloc[0]['action']} / {evidence_df.iloc[0]['status']} at {evidence_df.iloc[0]['timestamp']}

2. ATTACK PATH RECONSTRUCTION ({algorithm})
   - Reconstructed Path : {' -> '.join(active_path)}
   - Total Path Cost    : {active_cost}
   - Nodes Expanded     : {active_expanded}

3. SWI-PROLOG SYMBOLIC VERDICT
   - Critical Breach       : {'CONFIRMED' if breaches else 'NO'}
   - Unauthorized Access   : {'TRUE' if unauth_hits else 'FALSE'}
   - Log Tampering         : {'TRUE' if tamper_hits else 'FALSE'}
   - Off-Hours Exfiltration: {'TRUE' if exfil_hits else 'FALSE'}
"""
        st.download_button(
            label="📥 Download Incident Report (.txt)",
            data=report_text,
            file_name="AEGIS_Forensic_Report.txt",
            mime="text/plain",
            use_container_width=True,
        )