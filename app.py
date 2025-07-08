import streamlit as st
import pandas as pd
import numpy as np
import pickle
import io
import time
from datetime import datetime
from google.cloud import storage
import altair as alt

# Cấu hình giao diện rộng
st.set_page_config(layout="wide")
st.title("🔥 Realtime DDoS Monitor Dashboard")

# Khai báo các biến cố định
MODEL_DIR = 'models'
BUCKET_NAME = 'ddos_monitor'
PREFIX = 'incoming/'
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
    'idle_max', 'idle_min']

# Tải model và scaler
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

# Tải file mới nhất từ GCS
def load_latest_parquet():
    client = storage.Client()
    bucket = client.bucket(BUCKET_NAME)
    blobs = list(bucket.list_blobs(prefix=PREFIX))
    if not blobs:
        return pd.DataFrame()
    latest_blob = sorted(blobs, key=lambda b: b.updated, reverse=True)[0]
    return pd.read_parquet(io.BytesIO(latest_blob.download_as_bytes()))

# Hàm dự đoán và thêm timestamp
def predict(df, binary_model, multi_model, binary_scaler, multi_scaler, label_mapping):
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

    timestamp = datetime.now().strftime("%H:%M:%S")
    results = []
    for i in range(len(df)):
        results.append({
            "Source IP": df.iloc[i].get("src_ip", "N/A"),
            "Dest IP": df.iloc[i].get("dst_ip", "N/A"),
            "Src Port": df.iloc[i].get("src_port", 0),
            "Dst Port": df.iloc[i].get("dst_port", 0),
            "Duration (ms)": df.iloc[i].get("flow_duration", 0),
            "Packets": df.iloc[i].get("total_fwd_packet", 0) + df.iloc[i].get("total_bwd_packets", 0),
            "Prediction": "ATTACK" if binary_preds[i] == 1 else "BENIGN",
            "Confidence": float(np.max(binary_probs[i])),
            "Attack Type": attack_types[i],
            "Timestamp": timestamp
        })
    return pd.DataFrame(results)

# === MAIN ===
binary_model, multi_model, binary_scaler, multi_scaler, label_mapping = load_models()

# Vùng placeholder giao diện
placeholder_chart = st.empty()
placeholder_warning = st.empty()
placeholder_table = st.empty()

data_log = pd.DataFrame()
refresh_interval = 10  # giây
attack_threshold = 30  # ngưỡng cảnh báo

while True:
    df = load_latest_parquet()
    if df.empty:
        time.sleep(refresh_interval)
        st.rerun()

    df = df.sort_values("flow_duration", ascending=False).head(100)
    result_df = predict(df, binary_model, multi_model, binary_scaler, multi_scaler, label_mapping)

    # Gộp dữ liệu mới nhất vào log
    data_log = pd.concat([result_df, data_log], ignore_index=True).drop_duplicates()
    data_log = data_log.sort_values(by="Timestamp", ascending=False).head(300)

    # Tính toán số lượng BENIGN / ATTACK
    count_df = data_log["Prediction"].value_counts().reset_index()
    count_df.columns = ["Prediction", "Count"]

    # Biểu đồ tròn
    pie_chart = alt.Chart(count_df).mark_arc(innerRadius=50).encode(
        theta="Count:Q",
        color=alt.Color("Prediction:N", scale=alt.Scale(domain=["BENIGN", "ATTACK"], range=["green", "red"])),
        tooltip=["Prediction:N", "Count:Q"]
    ).properties(title="Tỷ lệ lưu lượng mạng", height=300)

    placeholder_chart.altair_chart(pie_chart, use_container_width=True)

    # Hiển thị cảnh báo hệ thống
    attack_count = int(count_df[count_df["Prediction"] == "ATTACK"]["Count"].sum()) if "ATTACK" in count_df["Prediction"].values else 0
    if attack_count >= attack_threshold:
        placeholder_warning.error(f"🚨 CẢNH BÁO: Hệ thống đang bị tấn công! ({attack_count} dòng ATTACK ≥ ngưỡng {attack_threshold})")
    else:
        placeholder_warning.success(f"✅ Hệ thống vẫn an toàn ({attack_count} dòng ATTACK dưới ngưỡng {attack_threshold})")

    # Hiển thị bảng
    with placeholder_table:
        st.markdown(f"### Kết quả dự đoán lúc {datetime.now().strftime('%H:%M:%S')} ⏳")
        st.dataframe(
            data_log.reset_index(drop=True),
            use_container_width=True,
            hide_index=True
        )

    time.sleep(refresh_interval)
    st.rerun()
