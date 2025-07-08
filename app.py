from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pandas as pd
import numpy as np
import pickle
from datetime import datetime
from collections import deque
from google.cloud import storage
import io
import os
import traceback

app = Flask(__name__)
CORS(app)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
BUCKET_NAME = "ddos_monitor"

# === Load models and scalers ===
with open(os.path.join(MODEL_DIR, 'top3_binary_xgboost_init_model.pkl'), 'rb') as f:
    binary_model = pickle.load(f)
with open(os.path.join(MODEL_DIR, 'top3_multi_xgboost_init_model.pkl'), 'rb') as f:
    multi_model = pickle.load(f)
with open(os.path.join(MODEL_DIR, 'binary_scaler_final.pkl'), 'rb') as f:
    binary_scaler = pickle.load(f)
with open(os.path.join(MODEL_DIR, 'multi_scaler_initial.pkl'), 'rb') as f:
    multi_scaler = pickle.load(f)
with open(os.path.join(MODEL_DIR, 'label_mapping_moinhat_xaidi (1).pkl'), 'rb') as f:
    label_mapping = pickle.load(f)

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
    'active_mean', 'active_std', 'active_max', 'active_min',
    'idle_mean', 'idle_std', 'idle_max', 'idle_min'
]

flows_data = deque(maxlen=1000)
monitoring_status = {"active": False, "last_update": None}

def load_latest_parquet_from_gcs():
    client = storage.Client()
    blobs = list(client.bucket(BUCKET_NAME).list_blobs(prefix="incoming/"))
    blobs = sorted(blobs, key=lambda b: b.updated, reverse=True)
    if not blobs:
        return pd.DataFrame()
    latest_blob = blobs[0]
    content = latest_blob.download_as_bytes()
    df = pd.read_parquet(io.BytesIO(content))

    # ✅ Đảm bảo đủ 67 đặc trưng để dự đoán
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    return df

@app.route("/api/flows", methods=["GET"])
def get_flows():
    try:
        df = load_latest_parquet_from_gcs()
        if df.empty:
            return jsonify({"flows": [], "statistics": {}, "monitoring_status": monitoring_status})

        original_df = df.copy()  # để hiển thị IP, Port sau khi dự đoán
        if 'label' in df.columns:
            df = df.drop(columns=['label'])

        # ✅ Tách dữ liệu đặc trưng để transform
        df_features = df[FEATURE_COLUMNS]
        X_binary = binary_scaler.transform(df_features)
        binary_preds = binary_model.predict(X_binary)
        binary_probs = binary_model.predict_proba(X_binary)

        attack_indices = np.where(binary_preds == 1)[0]
        attack_types = ["Benign"] * len(df)
        if len(attack_indices) > 0:
            X_attack = df_features.iloc[attack_indices]
            X_attack_scaled = multi_scaler.transform(X_attack)
            multi_preds = multi_model.predict(X_attack_scaled)
            for idx, pred in zip(attack_indices, multi_preds):
                attack_types[idx] = label_mapping.get(pred, "Unknown")

        results = []
        for i in range(len(df)):
            result = {
                "src_ip": original_df.iloc[i].get("src_ip", "N/A"),
                "dst_ip": original_df.iloc[i].get("dst_ip", "N/A"),
                "src_port": original_df.iloc[i].get("src_port", 0),
                "dst_port": original_df.iloc[i].get("dst_port", 0),
                "duration": original_df.iloc[i].get("flow_duration", 0),
                "packets": original_df.iloc[i].get("total_fwd_packet", 0) + original_df.iloc[i].get("total_bwd_packets", 0),
                "prediction": "ATTACK" if binary_preds[i] == 1 else "BENIGN",
                "confidence": float(np.max(binary_probs[i])),
                "attack_type": attack_types[i],
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)

        flows_data.extend(results)
        monitoring_status["last_update"] = datetime.now().isoformat()

        attack_flows = [f for f in results if f['prediction'] == 'ATTACK']
        benign_flows = [f for f in results if f['prediction'] == 'BENIGN']
        threat_level = "HIGH" if len(attack_flows) > 15 else "MEDIUM" if len(attack_flows) > 5 else "LOW"

        return jsonify({
            "flows": results[-50:],
            "statistics": {
                "total_flows": len(results),
                "attack_flows": len(attack_flows),
                "benign_flows": len(benign_flows),
                "threat_level": threat_level
            },
            "monitoring_status": monitoring_status
        })

    except Exception as e:
        print("[ERROR]", traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/api/monitoring/start", methods=["POST"])
def start_monitoring():
    monitoring_status["active"] = True
    monitoring_status["last_update"] = datetime.now().isoformat()
    return jsonify({"status": "started", "timestamp": monitoring_status["last_update"]})

@app.route("/api/monitoring/stop", methods=["POST"])
def stop_monitoring():
    monitoring_status["active"] = False
    monitoring_status["last_update"] = datetime.now().isoformat()
    return jsonify({"status": "stopped", "timestamp": monitoring_status["last_update"]})

@app.route("/api/monitoring/status", methods=["GET"])
def get_status():
    return jsonify(monitoring_status)

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
