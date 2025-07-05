import streamlit as st
import pandas as pd
import numpy as np
import joblib
import subprocess
import logging
import altair as alt
from streamlit_autorefresh import st_autorefresh

# ---------------------------
# Configuration and Setup
# ---------------------------

CSV_FILE = 'Outputs/captured_flows.csv'
LOG_FILE = 'Logs/app.log'

st.title('Real-Time IDS Dashboard (Guardnet UI + Custom Logic)')

logging.basicConfig(
    level=logging.INFO,
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ------- Feature names -------
feature_names = [
    'flow_duration', 'total_fwd_packet', 'total_bwd_packets', 'total_length_of_fwd_packet',
    'total_length_of_bwd_packet', 'fwd_packet_length_max', 'fwd_packet_length_min',
    'fwd_packet_length_mean', 'fwd_packet_length_std', 'bwd_packet_length_max',
    'bwd_packet_length_min', 'bwd_packet_length_mean', 'bwd_packet_length_std',
    'flow_bytes/s', 'flow_packets/s', 'flow_iat_mean', 'flow_iat_std', 'flow_iat_max',
    'flow_iat_min', 'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max',
    'fwd_iat_min', 'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max',
    'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
    'fwd_header_length', 'bwd_header_length', 'fwd_packets/s', 'bwd_packets/s',
    'packet_length_min', 'packet_length_max', 'packet_length_mean', 'packet_length_std',
    'packet_length_variance', 'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
    'psh_flag_count', 'ack_flag_count', 'urg_flag_count', 'ece_flag_count',
    'down/up_ratio', 'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets',
    'subflow_bwd_bytes', 'fwd_init_win_bytes', 'bwd_init_win_bytes', 'fwd_act_data_pkts',
    'fwd_seg_size_min', 'active_mean', 'active_std', 'active_max', 'active_min',
    'idle_mean', 'idle_std', 'idle_max', 'idle_min'
]

# ------- Attack names -------
attack_names = {
    0: "Benign", 1: "DrDoS_DNS", 2: "DrDoS_LDAP", 3: "DrDoS_MSSQL", 4: "DrDoS_NTP",
    5: "DrDoS_NetBIOS", 6: "DrDoS_SNMP", 7: "DrDoS_UDP", 8: "LDAP", 9: "MSSQL",
    10: "NetBIOS", 11: "Portmap", 12: "Syn", 13: "TFTP", 14: "UDP", 15: "UDP-lag",
    16: "UDPLag", 17: "WebDDoS"
}

# ------- Load models -------
binary_model = joblib.load("models/top3_binary_xgboost_init_model.pkl")
multi_model = joblib.load("models/top3_multi_xgboost_init_model.pkl")
scaler = joblib.load("models/multi_scaler_initial.pkl")

# ---------------------------
# Session State Initialization
# ---------------------------

if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = set()

# ---------------------------
# Helper Functions
# ---------------------------

def block_ip(ip):
    if ip and not ip.startswith(('10.', '192.168.', '172.')):
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd)
        logging.info(f"Blocked IP: {ip}")
        st.session_state['blocked_ips'].add(ip)

def unblock_ip(ip):
    if ip and not ip.startswith(('10.', '192.168.', '172.')):
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd)
        logging.info(f"Unblocked IP: {ip}")
        st.session_state['blocked_ips'].discard(ip)

@st.cache_data(ttl=2)
def read_and_process_data(csv_file):
    try:
        df = pd.read_csv(csv_file)
    except (pd.errors.EmptyDataError, FileNotFoundError):
        return pd.DataFrame(), pd.Series(dtype=int)

    if df.empty:
        return df, pd.Series(dtype=int)

    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
    df_features = df[feature_names].fillna(0).replace([np.inf, -np.inf], 0)

    # Dự đoán nhị phân
    X = scaler.transform(df_features)
    y_binary = binary_model.predict(X)

    # Dự đoán đa lớp nếu là attack
    y_multi = []
    for idx, pred in enumerate(y_binary):
        if pred == 1:
            attack_type = int(multi_model.predict(X[idx:idx+1])[0])
            y_multi.append(attack_type)
        else:
            y_multi.append(0)

    df['Prediction'] = y_binary
    df['AttackType'] = y_multi

    # Block IP tự động nếu là attack
    for idx, row in df.iterrows():
        if row['Prediction'] == 1:
            src_ip = row.get('src_ip', None)
            if src_ip and src_ip not in st.session_state['blocked_ips']:
                block_ip(src_ip)

    # Đếm attacker IPs
    attack_df = df[df['Prediction'] == 1]
    if 'src_ip' in attack_df.columns:
        public_ips = attack_df[~attack_df['src_ip'].astype(str).str.startswith(('10.', '172.', '192.168.100'))]
        attacker_ips = public_ips['src_ip'].value_counts()
    else:
        attacker_ips = pd.Series(dtype=int)

    return df, attacker_ips

# ---------------------------
# Streamlit Application Structure
# ---------------------------

def main():
    st.sidebar.title("Navigation")
    selected_tab = st.sidebar.radio("Select a tab", ["Dashboard", "Logs"])

    if selected_tab == "Dashboard":
        dashboard_tab()
    elif selected_tab == "Logs":
        logs_tab()

def dashboard_tab():
    st.header("Dashboard")
    st_autorefresh(interval=2000, limit=None, key="datarefresh")

    # Đọc và xử lý dữ liệu
    df, ips = read_and_process_data(CSV_FILE)

    if not df.empty:
        detected_attacks = df['Prediction'].value_counts()
        detected_attacks = detected_attacks.drop(index=0, errors='ignore')

        if not detected_attacks.empty:
            st.warning("🚨 Attack(s) detected!")

            # Map nhãn
            attack_counts = df['AttackType'].map(attack_names).value_counts()
            attack_data = attack_counts.reset_index()
            attack_data.columns = ['Attack Type', 'Count']

            st.markdown("### Detected Attack Types and Occurrences:")
            for _, row in attack_data.iterrows():
                st.write(f"**{row['Attack Type']}:** {row['Count']} occurrence(s)")

            # Bar chart Altair
            st.markdown("### Attack Types Distribution")
            chart = alt.Chart(attack_data).mark_bar(color='firebrick').encode(
                x=alt.X('Attack Type', sort='-y', title='Attack Type'),
                y=alt.Y('Count', title='Number of Occurrences'),
                tooltip=['Attack Type', 'Count']
            ).properties(
                width=700,
                height=400,
                title='Attack Types Distribution'
            ).configure_title(
                fontSize=20,
                anchor='middle'
            ).configure_axis(
                labelFontSize=12,
                titleFontSize=14
            )
            st.altair_chart(chart, use_container_width=True)

            # Attacker IPs
            st.markdown("### Attacker IPs:")
            if not ips.empty:
                top_ip = ips.idxmax()
                top_ip_count = ips.max()
                col1, col2 = st.columns([3, 1])
                col1.write(f"**{top_ip}**: {top_ip_count} attack(s)")
                if top_ip not in st.session_state['blocked_ips']:
                    if col2.button(f"Block {top_ip}", key=f"block_{top_ip}"):
                        block_ip(top_ip)
                        st.success(f"Blocked IP {top_ip}")
                else:
                    col2.write("Already blocked")
        else:
            st.success("✅ No attack detected.")

        # Raw data expander
        with st.expander("Show Captured Data"):
            st.dataframe(df)
    else:
        st.info("No captured data available. Waiting for flows...")

def logs_tab():
    st.header("Logs and Blocked IPs")
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.read()
        st.subheader("Log File Contents")
        st.text_area("Logs", logs, height=300)
    except FileNotFoundError:
        st.warning("Log file not found.")

    if st.session_state['blocked_ips']:
        st.subheader("Blocked IPs")
        for ip in sorted(st.session_state['blocked_ips']):
            col1, col2 = st.columns([3, 1])
            col1.write(ip)
            if col2.button(f"Unblock {ip}", key=f"unblock_{ip}"):
                unblock_ip(ip)
                st.success(f"Unblocked {ip}")
    else:
        st.info("No IPs have been blocked.")

if __name__ == "__main__":
    main()
