from nfstream import NFStreamer
import pandas as pd
import time

def collect_flows(interface="eth0", output_csv="Outputs/captured_flows.csv", batch_size=100):
    while True:
        streamer = NFStreamer(source=interface, decode_tunnels=True, snapshot_length=1536)
        flows = []
        for flow in streamer:
            flows.append(flow.to_dict())
            if len(flows) >= batch_size:
                break
        df = pd.DataFrame(flows)
        # Append vào file CSV (hoặc ghi đè tuỳ nhu cầu)
        if not df.empty:
            df.to_csv(output_csv, mode='w', index=False)
        time.sleep(1)

if __name__ == "__main__":
    collect_flows()
