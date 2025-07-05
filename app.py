import streamlit as st
import pandas as pd
import numpy as np
import joblib
from block_ip import block_ip, unblock_ip

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

st.title("Real-Time IDS Dashboard (Guardnet UI + Custom Logic)")

if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = set()

# Đọc dữ liệu realtime
try:
    df_full = pd.read_csv("Outputs/captured_flows.csv")
except Exception:
    df_full = pd.DataFrame()

if not df_full.empty:
    # Đảm bảo đủ cột feature
    for col in feature_names:
        if col not in df_full.columns:
            df_full[col] = 0
    df_features = df_full[feature_names].fillna(0).replace([np.inf, -np.inf], 0)

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

    df_full['Prediction'] = y_binary
    df_full['AttackType'] = y_multi

    # Block IP tự động nếu là attack
    for idx, row in df_full.iterrows():
        if row['Prediction'] == 1:
            src_ip = row.get('src_ip', None)
            if src_ip and src_ip not in st.session_state['blocked_ips']:
                block_ip(src_ip)
                st.session_state['blocked_ips'].add(src_ip)

    # Hiển thị dashboard như guardnet
    st.subheader("Detected Traffic")
    display_df = df_full[['src_ip', 'dst_ip', 'Prediction', 'AttackType']]
    display_df['AttackType'] = display_df['AttackType'].map(attack_names)
    display_df['Prediction'] = display_df['Prediction'].map({0: "Benign", 1: "Attack"})
    st.dataframe(display_df)

    # Thống kê attack
    attack_counts = display_df['AttackType'].value_counts()
    st.bar_chart(attack_counts)

    # Quản lý block/unblock IP
    st.subheader("Blocked IPs")
    for ip in list(st.session_state['blocked_ips']):
        col1, col2 = st.columns([3, 1])
        col1.write(ip)
        if col2.button(f"Unblock {ip}", key=f"unblock_{ip}"):
            unblock_ip(ip)
            st.session_state['blocked_ips'].remove(ip)
            st.success(f"Unblocked {ip}")

else:
    st.info("No captured data available. Waiting for flows...")

st.markdown("---")
st.caption("UI dựa trên GuardNet, logic theo pipeline nhị phân → đa lớp → block IP tự động.")
