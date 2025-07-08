import streamlit as st
import pandas as pd
import numpy as np
import pickle
import io
import time
from datetime import datetime
from google.cloud import storage

# ==== Config ====
st.set_page_config(page_title="DDoS Log Monitor", layout="wide")

MODEL_DIR = 'models'
BUCKET_NAME = 'ddos_monitor'
PREFIX = 'incoming/'
REFRESH_INTERVAL = 10  # giây

FEATURE_COLUMNS = [
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
    'psh_flag_count', 'ack_flag_count', 'urg_flag_count', 'ece_flag_count', 'down/up_ratio',
    'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
    'fwd_init_win_bytes', 'bwd_init_win_bytes', 'fwd_act_data_pkts', 'fwd_seg_size_min',
    'active_mean', 'active_std', 'active_max', 'active_min', 'idle_mean', 'idle_std',
    'idle_max', 'idle_min'
]

@st.cache_resource
def load_models():
    with open(f'{MODEL_DIR}/top3_binary_xgboost_init_model.pkl', 'rb') as f:
        binary_model = pickle.load(f)
    with open(f'{MODEL_DIR}/top3_multi_xgboost_init_model.pkl', 'rb') as f:
        multi_model = pickle.load(f)
    with open(f'{MODEL_DIR}/binary_scaler_final.pkl', 'rb') as f:
        binary_scaler = pickle.load(f)
    with open(f'{MODEL_DIR}/multi_scaler_initial.pkl', 'rb') as f:
        multi_scaler = pickle.load(f)
    with open(f'{MODEL_DIR}/label_mapping_moinhat_xaidi (1).pkl', 'rb') as f:
        label_mapping = pickle.load(f)
    return binary_model, multi_model, binary_scaler, multi_scaler, label_mapping

def load_latest_parquet():
    client = storage.Client()
    bucket = client.bucket(BUCKET_NAME)
    blobs = list(bucket.list_blobs(prefix=PREFIX))
    if not blobs:
        return None
    latest_blob = sorted(blobs, key=lambda b: b.updated, reverse=True)[0]
    return pd.read_parquet(io.BytesIO(latest_blob.download_as_bytes()))

def predict_ddos(df, binary_model, multi_model, binary_scaler, multi_scaler, label_mapping):
    df_features = df[FEATURE_COLUMNS].fillna(0)
    X_binary = binary_scaler.transform(df_features)
    binary_preds = binary_model.predict(X_binary)
    binary_probs = binary_model.predict_proba(X_binary)

    attack_types = ["Benign"] * len(df)
    attack_indices = np.where(binary_preds == 1)[0]
    if len(attack_indices) > 0:
        X_attack = df_features.iloc[attack_indices]
        X_attack_scaled = multi_scaler.transform(X_attack)
        multi_preds = multi_model.predict(X_attack_scaled)
        for idx, pred in zip(attack_indices, multi_preds):
            attack_types[idx] = label_mapping.get(pred, "Unknown")

    log_lines = []
    for i in range(len(df)):
        line = f"[{datetime.now().strftime('%H:%M:%S')}] "
        line += f"{df.iloc[i]['src_ip']}:{df.iloc[i]['src_port']} -> {df.iloc[i]['dst_ip']}:{df.iloc[i]['dst_port']} | "
        line += f"Packets={df.iloc[i]['total_fwd_packet'] + df.iloc[i]['total_bwd_packets']} | "
        line += f"{'ATTACK' if binary_preds[i] == 1 else 'BENIGN'} | "
        line += f"Confidence={np.max(binary_probs[i]):.3f} | Type={attack_types[i]}"
        log_lines.append(line)
    return "\n".join(log_lines)

# === MAIN ===
binary_model, multi_model, binary_scaler, multi_scaler, label_mapping = load_models()

st.title("🔥 Realtime DDoS Log Monitor")

log_area = st.empty()

while True:
    df = load_latest_parquet()
    if df is not None:
        df = df.sort_values("flow_duration", ascending=False).head(20)
        logs = predict_ddos(df, binary_model, multi_model, binary_scaler, multi_scaler, label_mapping)
        log_area.code(logs, language="text")
    else:
        log_area.warning("❗ Không tìm thấy dữ liệu parquet.")

    time.sleep(REFRESH_INTERVAL)
    st.rerun()
