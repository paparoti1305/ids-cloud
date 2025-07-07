# ================= app.py =================
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import pickle
from datetime import datetime
from collections import deque

app = Flask(__name__)
CORS(app)

import os

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

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


flows_data = deque(maxlen=1000)
monitoring_status = {"active": False, "last_update": None}

@app.route("/api/flows", methods=["POST"])
def receive_flows():
    try:
        data = request.get_json()
        if not data or 'flows' not in data:
            return jsonify({"error": "Invalid input"}), 400

        df = pd.DataFrame(data['flows'])
        if df.empty:
            return jsonify({"error": "Empty flow data"}), 400

        original_df = df.copy()
        if 'label' in df.columns:
            df = df.drop(columns=['label'])

        X_binary = binary_scaler.transform(df)
        binary_preds = binary_model.predict(X_binary)
        binary_probs = binary_model.predict_proba(X_binary)

        attack_indices = np.where(binary_preds == 1)[0]
        attack_types = ["Benign"] * len(df)
        if len(attack_indices) > 0:
            X_attack = df.iloc[attack_indices]
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

        return jsonify({"status": "success", "processed_flows": len(results), "predictions": results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/flows", methods=["GET"])
def get_flows():
    limit = request.args.get("limit", 50, type=int)
    recent = list(flows_data)[-limit:]
    attack_flows = [f for f in recent if f['prediction'] == 'ATTACK']
    benign_flows = [f for f in recent if f['prediction'] == 'BENIGN']
    threat_level = "HIGH" if len(attack_flows) > 15 else "MEDIUM" if len(attack_flows) > 5 else "LOW"

    return jsonify({
        "flows": recent,
        "statistics": {
            "total_flows": len(recent),
            "attack_flows": len(attack_flows),
            "benign_flows": len(benign_flows),
            "threat_level": threat_level
        },
        "monitoring_status": monitoring_status
    })

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
from flask import render_template

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
