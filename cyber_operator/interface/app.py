"""
Streamlit Web Interface
Main dashboard for Cyber Operator
"""

import streamlit as st
import json
from datetime import datetime
from typing import List, Dict

from cyber_operator.core import (
    Orchestrator, TargetType, SelectionMode
)
from cyber_operator.config import Config
from cyber_operator.database import DatabaseManager


# Page configuration
st.set_page_config(
    page_title="Cyber Operator",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

if 'db' not in st.session_state:
    st.session_state.db = DatabaseManager(Config.DATABASE_PATH)

if 'orchestrator' not in st.session_state:
    st.session_state.orchestrator = Orchestrator(
        database_manager=st.session_state.db
    )

# Styling
st.markdown("""
    <style>
        .title-section {
            text-align: center;
            padding: 20px 0;
            border-bottom: 2px solid #1f77b4;
        }
        .metric-card {
            background-color: #f0f2f6;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .success-box {
            background-color: #d4edda;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .error-box {
            background-color: #f8d7da;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .warning-box {
            background-color: #fff3cd;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
    </style>
""", unsafe_allow_html=True)


def display_header():
    """Display main header"""
    st.markdown("""
    <div class="title-section">
        <h1>🔍 CYBER OPERATOR</h1>
        <h3>INTELLIGENCE SEARCH ENGINE</h3>
        <p>Centralized platform for cybersecurity intelligence gathering and analysis</p>
    </div>
    """, unsafe_allow_html=True)


def display_source_status():
    """Display available sources and their status"""
    orchestrator = st.session_state.orchestrator
    
    st.subheader("📊 Available Sources")
    
    sources = orchestrator.get_available_sources()
    
    # Create columns for source display
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Sources", len(sources))
    
    with col2:
        active = len([s for s in sources if s['active']])
        st.metric("Active", active)
    
    with col3:
        external = len([s for s in sources if s['type'] == 'external_api'])
        st.metric("External APIs", external)
    
    with col4:
        local = len([s for s in sources if s['type'] == 'local_tool'])
        st.metric("Local Tools", local)
    
    # Source table
    st.write("### Source Details")
    
    df_data = []
    for source in sources:
        df_data.append({
            "Source ID": source['id'],
            "Name": source['name'],
            "Type": source['type'].replace('_', ' ').title(),
            "Category": source['category'],
            "Status": "✅ Active" if source['active'] else "❌ Inactive",
            "Availability": source["availability"].replace("_", " ").title(),
            "Credentials": source["credentials_status"].replace("_", " ").title(),
            "Requires Credentials": "Yes" if source['requires_credentials'] else "No"
        })
    
    st.dataframe(df_data, use_container_width=True)


def display_target_classification(target: str) -> Dict:
    """Display target classification results"""
    orchestrator = st.session_state.orchestrator
    
    analysis = orchestrator.analyze_target(target)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("### Target Analysis")
        st.write(f"**Target:** `{analysis['target']}`")
        st.write(f"**Type:** `{analysis['type'].upper()}`")
    
    with col2:
        st.write("### Compatible Categories")
        for category in analysis['compatible_categories']:
            st.write(f"- {category}")
    
    return analysis


def display_source_selection(target_type: str, categories: List[str], target: str):
    """Display source selection interface"""
    orchestrator = st.session_state.orchestrator
    
    st.subheader("🎯 Source Selection")
    
    all_sources = orchestrator.get_available_sources()
    
    selected_source_ids = []
    
    for source in all_sources:
        if (
            not source["active"]
            or target_type not in source["supported_targets"]
            or source["category"] not in categories
            or not orchestrator.engine.is_compatible(
                orchestrator.registry.get_source(source["id"]),
                target,
                target_type,
            )
        ):
            continue
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"**{source['name']}** - {source['description']}")
            st.caption(
                f"Availability: {source['availability'].replace('_', ' ').title()} | "
                f"Priority: {source.get('priority', 5)}/10"
            )
        with col2:
            available = source["availability"] == "available"
            if st.checkbox(
                "Select",
                key=f"source_{source['id']}",
                value=available,
                disabled=not available,
            ):
                selected_source_ids.append(source['id'])
    
    return selected_source_ids


def display_query_execution(target: str, mode: str, source_ids: List[str] = None):
    """Execute and display query results"""
    orchestrator = st.session_state.orchestrator
    
    with st.spinner("⏳ Executing intelligence queries..."):
        try:
            # Prepare query parameters
            if mode == "manual" and source_ids:
                from cyber_operator.core import IntelligenceQuery
                query = IntelligenceQuery(
                    target=target,
                    selection_mode=SelectionMode.MANUAL,
                    source_ids=source_ids
                )
            else:
                from cyber_operator.core import IntelligenceQuery
                query = IntelligenceQuery(
                    target=target,
                    selection_mode=SelectionMode[mode.upper()]
                )
            
            # Execute query
            results = orchestrator.execute_query(query)
            
            return results
        
        except Exception as e:
            st.error(f"Query execution error: {str(e)}")
            return None


def display_results(results: Dict):
    """Display query results"""
    if not results:
        st.error("No results to display")
        return
    
    if not results.get('success'):
        st.error(f"Query failed: {results.get('error', 'Unknown error')}")
        if not results.get('findings'):
            return
    
    # Summary section
    st.subheader("📈 Query Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    summary = results['execution_summary']
    
    with col1:
        st.metric("Total Queries", summary['total_queries'])
    with col2:
        st.metric("Successful", summary['successful'])
    with col3:
        st.metric("Success Rate", f"{summary['success_rate']:.1f}%")
    with col4:
        st.metric("Total Time", f"{summary['total_execution_time']:.2f}s")
    
    # Findings section
    findings = results['findings']
    
    st.subheader("🔍 Findings")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Risk Level", findings['risk_assessment']['level'])
    with col2:
        st.metric("Risk Score", findings['risk_assessment']['score'])
    with col3:
        st.metric("Sources Queried", findings['summary']['total_sources_queried'])
    
    # Risk indicators
    st.caption(findings["risk_assessment"]["interpretation"])
    if findings['risk_assessment']['indicators']:
        st.write("### ⚠️ Risk Indicators")
        for indicator in findings['risk_assessment']['indicators']:
            st.write(f"- {indicator}")
    
    # Correlations
    if findings['correlations']['common_findings']:
        st.write("### 🔗 Correlated Findings")
        for finding, sources in findings['correlations']['common_findings'].items():
            st.write(f"- **{finding}** (mentioned by {len(sources)} sources)")
    
    # Detailed results by source
    st.write("### 📋 Results by Source")
    
    source_results = findings.get('sources', {})
    
    for source_id, source_data in source_results.items():
        with st.expander(f"📌 {source_data.get('source_name', source_id)}"):
            st.write(
                f"**Availability:** "
                f"{source_data['availability_status'].replace('_', ' ').title()}"
            )
            st.write(
                f"**Execution:** "
                f"{source_data['execution_status'].replace('_', ' ').title()}"
            )
            st.write(f"**Response time:** {source_data['execution_time']:.2f}s")
            if source_data.get("cached"):
                st.caption("Result served from SQLite cache.")
            if source_data['success']:
                st.success("Consulta exitosa" if source_data["execution_status"] != "cached"
                           else "Consulta exitosa (caché)")
                if source_data['data']:
                    st.write("**Original connector response**")
                    st.json(source_data['data'])
                    st.write("**Normalized and deduplicated view**")
                    st.json(source_data["normalized_data"])
            else:
                if source_data['error']:
                    st.error(source_data['error'])
                else:
                    st.info("No se ejecutó una consulta para esta fuente.")
                if source_data["data"]:
                    st.write("**Partial connector response**")
                    st.json(source_data["data"])
            if source_data.get("persistence_error"):
                st.warning(source_data["persistence_error"])

    for skipped in results.get("sources", {}).get("skipped", []):
        st.info(
            f"{skipped.get('source_name', skipped.get('source_id') or 'Manual selection')}: "
            f"{skipped['availability_status'].replace('_', ' ').title()} "
            "(not queried)"
        )


def main():
    """Main application"""
    
    # Display header
    display_header()
    
    # Sidebar
    with st.sidebar:
        st.write("## ⚙️ Configuration")
        
        st.write("### Categories")
        categories = st.session_state.orchestrator.get_categories()
        selected_categories = st.multiselect(
            "Categories (manual mode filter)",
            categories,
            default=categories
        )
        
        st.write("### Query Mode")
        query_mode = st.radio(
            "Select query mode",
            ["all", "recommended", "manual"]
        )
        
        if query_mode == "manual":
            st.write("Only compatible and available sources can be selected.")
    
    # Source status
    display_source_status()
    
    st.divider()
    
    # Main search interface
    st.subheader("🔎 Intelligence Search")
    
    target = st.text_input(
        "Enter search target",
        placeholder="domain.com, 192.168.1.1, hash, email, etc.",
        help="Enter domain, IP address, file hash, email, or other target"
    )

    analysis = display_target_classification(target) if target else None
    selected_source_ids = []
    if analysis and query_mode == "manual":
        selected_source_ids = display_source_selection(
            analysis["type"], selected_categories, target
        )

    search_button = st.button("🚀 Search", type="primary", use_container_width=True)
    
    if target and search_button:
        st.divider()
        
        # Execute query
        results = display_query_execution(
            target=target,
            mode=query_mode,
            source_ids=selected_source_ids
        )
        
        if results:
            st.divider()
            display_results(results)
            
            # Export options
            st.write("### 📥 Export Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                json_export = json.dumps(results, indent=2, default=str)
                st.download_button(
                    label="📄 Download as JSON",
                    data=json_export,
                    file_name=f"results_{results.get('query_id', 'query')}.json",
                    mime="application/json"
                )
            
            with col2:
                markdown_export = f"""# Intelligence Report for {target}

Generated: {datetime.now().isoformat()}
Query ID: {results.get('query_id', 'unknown')}

## Summary
- Total Queries: {results['execution_summary']['total_queries']}
- Success Rate: {results['execution_summary']['success_rate']:.1f}%
- Execution Time: {results['execution_summary']['total_execution_time']:.2f}s

## Risk Assessment
- Level: {results['findings']['risk_assessment']['level']}
- Score: {results['findings']['risk_assessment']['score']}
"""
                st.download_button(
                    label="📝 Download as Markdown",
                    data=markdown_export,
                    file_name=f"report_{results.get('query_id', 'query')}.md",
                    mime="text/markdown"
                )
    
    # History section
    st.divider()
    
    with st.expander("📜 Query History", expanded=False):
        db = st.session_state.db
        history = db.get_query_history(limit=20)
        
        if history:
            hist_data = []
            for record in history:
                hist_data.append({
                    "Target": record['target'],
                    "Type": record['target_type'],
                    "Mode": record['selection_mode'],
                    "Time": record['timestamp'],
                    "Query ID": record.get("query_id"),
                    "Status": record.get("status"),
                    "Success": "✅" if record['success'] else "❌"
                })
            st.dataframe(hist_data, use_container_width=True)
        else:
            st.info("No query history yet")


if __name__ == "__main__":
    main()
