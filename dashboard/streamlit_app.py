# Copyright (c) 2024 - DDoS Detection Project
# Streamlit Dashboard for DDoS Detection Monitoring
#
# Visualizations (as per CLAUDE.md Phase 11):
# - Total attacks detected
# - Attack types distribution
# - Top attacker IPs
# - Detection latency
# - CPU usage
# - Traffic before vs after mitigation
#
# Usage:
#   streamlit run dashboard/streamlit_app.py

import streamlit as st
import pandas as pd
import numpy as np
import os
import sys
import glob
import time
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Project paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_FOLDER = os.path.join(PROJECT_ROOT, "logs")
OUTPUT_FOLDER = os.path.join(PROJECT_ROOT, "output")
MODELS_FOLDER = os.path.join(PROJECT_ROOT, "models")

st.set_page_config(
    page_title="DDoS Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 15px;
        padding: 1.5rem;
        border: 1px solid rgba(102, 126, 234, 0.3);
    }
    .stMetric {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
        border-radius: 12px;
        padding: 1rem;
        border: 1px solid rgba(102, 126, 234, 0.2);
    }
    div[data-testid="stMetricValue"] {
        font-size: 2rem;
    }
</style>
""", unsafe_allow_html=True)


def load_attack_log():
    """Load attack log from CSV."""
    log_path = os.path.join(LOGS_FOLDER, "attack_log.csv")
    if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
        try:
            df = pd.read_csv(log_path)
            if 'Timestamp' in df.columns:
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])
            return df
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()


def load_predictions():
    """Load prediction results from output folder."""
    pred_files = glob.glob(os.path.join(OUTPUT_FOLDER, "predictions-*.csv"))
    if pred_files:
        latest = max(pred_files, key=os.path.getmtime)
        try:
            return pd.read_csv(latest)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()


def load_evaluation_log():
    """Load evaluation results."""
    eval_path = os.path.join(LOGS_FOLDER, "evaluation_log.csv")
    if os.path.exists(eval_path):
        try:
            return pd.read_csv(eval_path)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()


def load_model_info():
    """Load model metadata."""
    model_files = glob.glob(os.path.join(OUTPUT_FOLDER, "*.joblib"))
    if not model_files:
        model_files = glob.glob(os.path.join(MODELS_FOLDER, "*.pkl")) + \
                      glob.glob(os.path.join(MODELS_FOLDER, "*.joblib"))
    info = []
    for mf in model_files:
        stat = os.stat(mf)
        info.append({
            'Model': os.path.basename(mf),
            'Size_MB': stat.st_size / (1024*1024),
            'Modified': time.ctime(stat.st_mtime)
        })
    return info


def generate_demo_data():
    """Generate demo data for visualization when no real logs exist."""
    np.random.seed(42)
    n = 200
    timestamps = pd.date_range('2024-01-01', periods=n, freq='30s')
    src_ips = [f"192.168.{np.random.randint(1,5)}.{np.random.randint(1,255)}" for _ in range(n)]
    dst_ips = [f"10.0.0.{np.random.randint(1,5)}" for _ in range(n)]
    confidences = np.random.uniform(0.7, 0.99, n)
    det_times = np.random.uniform(5, 80, n)
    mit_times = np.random.uniform(500, 2000, n)
    actions = [f"SIMULATED_DROP(ip={ip})" for ip in src_ips]

    return pd.DataFrame({
        'Timestamp': timestamps,
        'Source_IP': src_ips,
        'Destination_IP': dst_ips,
        'Prediction': 'DDoS',
        'Confidence_Score': confidences,
        'Detection_Time_ms': det_times,
        'Mitigation_Time_ms': mit_times,
        'Action_Taken': actions
    })


def main():
    st.markdown('<h1 class="main-header">🛡️ DDoS Detection & Mitigation Dashboard</h1>', unsafe_allow_html=True)
    st.markdown("---")

    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
        st.title("Controls")
        auto_refresh = st.checkbox("Auto Refresh", value=False)
        if auto_refresh:
            refresh_interval = st.slider("Refresh interval (s)", 5, 60, 10)
        use_demo = st.checkbox("Use Demo Data", value=True)
        st.markdown("---")
        st.markdown("**System Info**")
        st.info(f"Project: SDN DDoS Detection\nAlgorithm: Random Forest\nFramework: LUCID")

    # Load data
    attack_log = load_attack_log()
    predictions = load_predictions()

    if attack_log.empty and use_demo:
        attack_log = generate_demo_data()
        st.info("📊 Showing demo data. Uncheck 'Use Demo Data' to see real logs.")

    # === KPI Cards ===
    st.subheader("📊 Key Performance Indicators")
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)

    total_attacks = len(attack_log)
    avg_detection = attack_log['Detection_Time_ms'].mean() if not attack_log.empty else 0
    avg_mitigation = attack_log['Mitigation_Time_ms'].mean() if not attack_log.empty else 0
    avg_confidence = attack_log['Confidence_Score'].mean() if not attack_log.empty else 0

    kpi1.metric("🎯 Total Attacks", f"{total_attacks:,}", delta="Detected")
    kpi2.metric("⚡ Avg Detection", f"{avg_detection:.1f} ms", delta="Target: <50ms")
    kpi3.metric("🛡️ Avg Mitigation", f"{avg_mitigation:.0f} ms", delta="Target: <1500ms")
    kpi4.metric("📈 Avg Confidence", f"{avg_confidence:.2%}")

    st.markdown("---")

    if not attack_log.empty:
        # === Charts Row 1 ===
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🏴‍☠️ Top Attacker IPs")
            top_ips = attack_log['Source_IP'].value_counts().head(10)
            st.bar_chart(top_ips)

        with col2:
            st.subheader("⏱️ Detection Latency Over Time")
            if 'Timestamp' in attack_log.columns:
                chart_data = attack_log[['Timestamp', 'Detection_Time_ms']].copy()
                chart_data = chart_data.set_index('Timestamp')
                st.line_chart(chart_data)
            else:
                st.line_chart(attack_log['Detection_Time_ms'])

        st.markdown("---")

        # === Charts Row 2 ===
        col3, col4 = st.columns(2)

        with col3:
            st.subheader("🎯 Confidence Score Distribution")
            hist_data = pd.cut(attack_log['Confidence_Score'], bins=20).value_counts().sort_index()
            st.bar_chart(hist_data)

        with col4:
            st.subheader("🎯 Target (Victim) IPs")
            victim_counts = attack_log['Destination_IP'].value_counts().head(10)
            st.bar_chart(victim_counts)

        st.markdown("---")

        # === Mitigation Analysis ===
        st.subheader("🛡️ Mitigation Performance")
        mit1, mit2 = st.columns(2)

        with mit1:
            st.markdown("**Detection vs Mitigation Time**")
            time_data = attack_log[['Detection_Time_ms', 'Mitigation_Time_ms']].copy()
            st.line_chart(time_data)

        with mit2:
            unique_attackers = attack_log['Source_IP'].nunique()
            unique_victims = attack_log['Destination_IP'].nunique()
            st.markdown("**Attack Summary**")
            st.metric("Unique Attackers", unique_attackers)
            st.metric("Unique Victims", unique_victims)
            st.metric("Total Events", len(attack_log))

        st.markdown("---")

        # === KPI Comparison with Paper ===
        st.subheader("📄 Comparison with Paper Results")
        paper_col1, paper_col2 = st.columns(2)

        with paper_col1:
            comparison = pd.DataFrame({
                'Metric': ['Accuracy', 'Detection Time', 'Mitigation Time'],
                'Paper': ['98.38%', '36 ms', '1179 ms'],
                'Our System': [
                    'See eval log',
                    f'{avg_detection:.1f} ms',
                    f'{avg_mitigation:.0f} ms'
                ],
                'Target': ['>98%', '<50 ms', '<1500 ms']
            })
            st.table(comparison)

        with paper_col2:
            eval_log = load_evaluation_log()
            if not eval_log.empty:
                st.markdown("**Latest Evaluation Results**")
                st.dataframe(eval_log)
            else:
                st.info("No evaluation log found. Run evaluate_model.py first.")

        st.markdown("---")

        # === Raw Log Table ===
        st.subheader("📋 Attack Event Log")
        st.dataframe(
            attack_log.sort_values('Timestamp', ascending=False) if 'Timestamp' in attack_log.columns else attack_log,
            use_container_width=True,
            height=400
        )

    else:
        st.warning("No attack data available. Run detection or enable demo data.")

    # === Model Info ===
    st.markdown("---")
    st.subheader("🤖 Model Information")
    model_info = load_model_info()
    if model_info:
        st.table(pd.DataFrame(model_info))
    else:
        st.info("No trained models found in output/ or models/ directory.")

    # Predictions
    if not predictions.empty:
        st.markdown("---")
        st.subheader("🔮 Prediction Results")
        st.dataframe(predictions, use_container_width=True)

    # Auto-refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        if hasattr(st, "rerun"):
            st.rerun()
        else:
            st.experimental_rerun()


if __name__ == "__main__":
    main()
