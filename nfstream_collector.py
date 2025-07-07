import requests
import pandas as pd
import time
from datetime import datetime
from nfstream import NFStreamer
import logging

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CollectorService:
    def __init__(self, interface="ens4", api_url="http://localhost:8080", duration=10):
        self.interface = interface
        self.api_url = api_url
        self.duration = duration

    def collect_and_preprocess(self):
        try:
            logger.info(f"Đang thu thập dữ liệu trong {self.duration} giây từ giao diện: {self.interface}...")
            streamer = NFStreamer(
                source=self.interface,
                decode_tunnels=True,
                snapshot_length=1536,
                active_timeout=self.duration,
                statistical_analysis=True
            )
            time.sleep(self.duration)
            df = streamer.to_pandas()

            if df.empty:
                logger.warning("Không có dữ liệu thu thập được")
                return None

            logger.info(f"Đã thu thập {len(df)} luồng.")

            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

            keep_columns = [
                'bidirectional_duration_ms', 'src2dst_packets', 'dst2src_packets',
                'src2dst_bytes', 'dst2src_bytes', 'src2dst_mean_ps', 'dst2src_mean_ps',
                'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'src2dst_mean_piat_ms',
                'dst2src_mean_piat_ms', 'src2dst_max_piat_ms', 'dst2src_max_piat_ms',
                'bidirectional_mean_piat_ms', 'bidirectional_max_piat_ms',
                'bidirectional_ack_packets', 'bidirectional_syn_packets',
                'src2dst_ack_packets', 'dst2src_ack_packets', 'src_port', 'dst_port',
                'src_ip', 'dst_ip'
            ]
            df = df[[col for col in keep_columns if col in df.columns]]

            numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns.tolist()
            for col in numeric_cols:
                df[col] = df[col].fillna(df[col].mean())

            df['label'] = -1

            missing_cols = [
                'flow_duration', 'total_fwd_packet', 'total_bwd_packets',
                'total_length_of_fwd_packet', 'total_length_of_bwd_packet',
                'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
                'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean', 'bwd_packet_length_std',
                'flow_bytes/s', 'flow_packets/s', 'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
                'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
                'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
                'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
                'fwd_header_length', 'bwd_header_length', 'fwd_packets/s', 'bwd_packets/s',
                'packet_length_min', 'packet_length_max', 'packet_length_mean', 'packet_length_std', 'packet_length_variance',
                'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 'urg_flag_count', 'ece_flag_count',
                'down/up_ratio', 'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
                'fwd_init_win_bytes', 'bwd_init_win_bytes', 'fwd_act_data_pkts', 'fwd_seg_size_min',
                'active_mean', 'active_std', 'active_max', 'active_min',
                'idle_mean', 'idle_std', 'idle_max', 'idle_min'
            ]

            df.rename(columns={
                'bidirectional_duration_ms': 'flow_duration',
                'src2dst_packets': 'total_fwd_packet',
                'dst2src_packets': 'total_bwd_packets',
                'src2dst_bytes': 'total_length_of_fwd_packet',
                'dst2src_bytes': 'total_length_of_bwd_packet',
                'src2dst_mean_ps': 'fwd_packets/s',
                'dst2src_mean_ps': 'bwd_packets/s',
                'bidirectional_mean_ps': 'flow_packets/s',
                'bidirectional_stddev_ps': 'packet_length_std',
                'src2dst_mean_piat_ms': 'fwd_iat_mean',
                'dst2src_mean_piat_ms': 'bwd_iat_mean',
                'src2dst_max_piat_ms': 'fwd_iat_max',
                'dst2src_max_piat_ms': 'bwd_iat_max',
                'bidirectional_mean_piat_ms': 'flow_iat_mean',
                'bidirectional_max_piat_ms': 'flow_iat_max',
                'bidirectional_ack_packets': 'ack_flag_count',
                'bidirectional_syn_packets': 'syn_flag_count',
                'src2dst_ack_packets': 'fwd_psh_flags',
                'dst2src_ack_packets': 'bwd_psh_flags'
            }, inplace=True)

            for col in missing_cols:
                if col not in df.columns:
                    df[col] = 0.0

            merged_cols = [
                'flow_duration', 'total_fwd_packet', 'total_bwd_packets', 'total_length_of_fwd_packet',
                'total_length_of_bwd_packet', 'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
                'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean', 'bwd_packet_length_std',
                'flow_bytes/s', 'flow_packets/s', 'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
                'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
                'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
                'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
                'fwd_header_length', 'bwd_header_length', 'fwd_packets/s', 'bwd_packets/s',
                'packet_length_min', 'packet_length_max', 'packet_length_mean', 'packet_length_std', 'packet_length_variance',
                'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 'urg_flag_count', 'ece_flag_count',
                'down/up_ratio', 'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
                'fwd_init_win_bytes', 'bwd_init_win_bytes', 'fwd_act_data_pkts', 'fwd_seg_size_min',
                'active_mean', 'active_std', 'active_max', 'active_min',
                'idle_mean', 'idle_std', 'idle_max', 'idle_min', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'label'
            ]
            available_cols = [col for col in merged_cols if col in df.columns]
            df = df[available_cols]
            logger.info(f"Dữ liệu đã được xử lý: {df.shape}")
            return df

        except Exception as e:
            logger.error(f"Lỗi khi thu thập dữ liệu: {e}")
            return None

    def send_to_api(self, df):
        try:
            flows_data = df.to_dict('records')
            response = requests.post(
                f"{self.api_url}/api/flows",
                json={"flows": flows_data},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Đã gửi {result.get('processed_flows', 0)} flows đến API")
                return True
            else:
                logger.error(f"API trả về lỗi: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Lỗi khi gửi dữ liệu đến API: {e}")
            return False

    def check_monitoring_status(self):
        try:
            res = requests.get(f"{self.api_url}/api/monitoring/status", timeout=10)
            return res.status_code == 200 and res.json().get("active", False)
        except Exception as e:
            logger.error(f"Lỗi kiểm tra trạng thái monitoring: {e}")
            return False

    def run_monitoring_loop(self):
        logger.info("Collector đang chạy và theo dõi trạng thái giám sát...")
        while True:
            if self.check_monitoring_status():
                df = self.collect_and_preprocess()
                if df is not None and not df.empty:
                    self.send_to_api(df)
            else:
                logger.info("Monitoring đang tắt. Đợi...")
            time.sleep(5)

if __name__ == "__main__":
    INTERFACE = "ens4"
    API_URL = "https://nhule-130504-724827159679.us-central1.run.app"
    DURATION = 10

    collector = CollectorService(
        interface=INTERFACE,
        api_url=API_URL,
        duration=DURATION
    )
    collector.run_monitoring_loop()
