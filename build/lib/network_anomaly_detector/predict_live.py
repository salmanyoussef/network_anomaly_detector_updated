from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time
import joblib
import os
from collections import defaultdict
import numpy as np
from scapy.utils import wrpcap

pd.set_option('display.max_rows', None)

packets = []

# Protocol map for mapping protocol numbers to names
protocol_map = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    88: "EIGRP",
    89: "OSPF",
    132: "SCTP"
}


def extract_features(packet):
    """
    Extract basic features from a packet.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = 1  # Default to ICMP
        src_port = dst_port = 0
        header_length = 0

        if TCP in packet:
            proto = 6
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            header_length = len(packet[TCP])  # TCP header length
        elif UDP in packet:
            proto = 17
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            header_length = len(packet[UDP])  # UDP header length
        else:
            header_length = len(packet[IP])  # Default to IP header length

        pkt_len = len(packet)
        timestamp = time.time()

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "packet_size": pkt_len,
            "timestamp": timestamp,
            "flags": packet.sprintf("%TCP.flags%") if TCP in packet else None,
            "header_length": header_length  # Include header length
        }
    return None


def process_flows(packets):
    """
    Process packets into flows and compute flow-level features.
    """
    flows = defaultdict(list)

    # Group packets into flows based on 5-tuple
    for pkt in packets:
        flow_key = (pkt["src_ip"], pkt["dst_ip"],
                    pkt["src_port"], pkt["dst_port"], pkt["protocol"])
        flows[flow_key].append(pkt)

    flow_features = []

    # Compute features for each flow
    for flow_key, flow_packets in flows.items():
        fwd_packets = [p for p in flow_packets if p["src_ip"] == flow_key[0]]
        bwd_packets = [p for p in flow_packets if p["src_ip"] != flow_key[0]]

        # Compute flow-level statistics
        flow_duration = flow_packets[-1]["timestamp"] - \
            flow_packets[0]["timestamp"]
        flow = {
            "Source IP": flow_key[0],
            "Destination IP": flow_key[1],
            "Source Port": flow_key[2],
            "Destination Port": flow_key[3],
            "Protocol": protocol_map.get(flow_key[4], flow_key[4]),            "Flow Duration": flow_duration,
            "Total Fwd Packets": len(fwd_packets),
            "Total Backward Packets": len(bwd_packets),
            "Total Length of Fwd Packets": sum(p["packet_size"] for p in fwd_packets),
            "Total Length of Bwd Packets": sum(p["packet_size"] for p in bwd_packets),
            "Fwd Packet Length Max": max((p["packet_size"] for p in fwd_packets), default=0),
            "Fwd Packet Length Min": min((p["packet_size"] for p in fwd_packets), default=0),
            "Fwd Packet Length Mean": np.mean([p["packet_size"] for p in fwd_packets]) if fwd_packets else 0,
            "Fwd Packet Length Std": np.std([p["packet_size"] for p in fwd_packets]) if fwd_packets else 0,
            "Bwd Packet Length Max": max((p["packet_size"] for p in bwd_packets), default=0),
            "Bwd Packet Length Min": min((p["packet_size"] for p in bwd_packets), default=0),
            "Bwd Packet Length Mean": np.mean([p["packet_size"] for p in bwd_packets]) if bwd_packets else 0,
            "Bwd Packet Length Std": np.std([p["packet_size"] for p in bwd_packets]) if bwd_packets else 0,
            "Flow Bytes/s": (sum(p["packet_size"] for p in flow_packets) /
                             (flow_duration if flow_duration > 0 else 1)),
            "Flow Packets/s": (len(flow_packets) /
                               (flow_duration if flow_duration > 0 else 1)),
            "Flow IAT Mean": np.mean(
                [flow_packets[i]["timestamp"] - flow_packets[i - 1]["timestamp"]
                 for i in range(1, len(flow_packets))]
            ) if len(flow_packets) > 1 else 0,
            "Flow IAT Std": np.std(
                [flow_packets[i]["timestamp"] - flow_packets[i - 1]["timestamp"]
                 for i in range(1, len(flow_packets))]
            ) if len(flow_packets) > 1 else 0,
            "Flow IAT Max": max(
                [flow_packets[i]["timestamp"] - flow_packets[i - 1]["timestamp"]
                 for i in range(1, len(flow_packets))]
            ) if len(flow_packets) > 1 else 0,
            "Flow IAT Min": min(
                [flow_packets[i]["timestamp"] - flow_packets[i - 1]["timestamp"]
                 for i in range(1, len(flow_packets))]
            ) if len(flow_packets) > 1 else 0,
            "Fwd IAT Total": sum(
                fwd_packets[i]["timestamp"] - fwd_packets[i - 1]["timestamp"]
                for i in range(1, len(fwd_packets))
            ) if len(fwd_packets) > 1 else 0,
            "Fwd IAT Mean": np.mean(
                [fwd_packets[i]["timestamp"] - fwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(fwd_packets))]
            ) if len(fwd_packets) > 1 else 0,
            "Fwd IAT Std": np.std(
                [fwd_packets[i]["timestamp"] - fwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(fwd_packets))]
            ) if len(fwd_packets) > 1 else 0,
            "Fwd IAT Max": max(
                [fwd_packets[i]["timestamp"] - fwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(fwd_packets))]
            ) if len(fwd_packets) > 1 else 0,
            "Fwd IAT Min": min(
                [fwd_packets[i]["timestamp"] - fwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(fwd_packets))]
            ) if len(fwd_packets) > 1 else 0,
            "Bwd IAT Total": sum(
                bwd_packets[i]["timestamp"] - bwd_packets[i - 1]["timestamp"]
                for i in range(1, len(bwd_packets))
            ) if len(bwd_packets) > 1 else 0,
            "Bwd IAT Mean": np.mean(
                [bwd_packets[i]["timestamp"] - bwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(bwd_packets))]
            ) if len(bwd_packets) > 1 else 0,
            "Bwd IAT Std": np.std(
                [bwd_packets[i]["timestamp"] - bwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(bwd_packets))]
            ) if len(bwd_packets) > 1 else 0,
            "Bwd IAT Max": max(
                [bwd_packets[i]["timestamp"] - bwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(bwd_packets))]
            ) if len(bwd_packets) > 1 else 0,
            "Bwd IAT Min": min(
                [bwd_packets[i]["timestamp"] - bwd_packets[i - 1]["timestamp"]
                 for i in range(1, len(bwd_packets))]
            ) if len(bwd_packets) > 1 else 0,
            "Fwd PSH Flags": sum(1 for p in fwd_packets if p["flags"] and "P" in p["flags"]),
            "Bwd PSH Flags": sum(1 for p in bwd_packets if p["flags"] and "P" in p["flags"]),
            "Fwd URG Flags": sum(1 for p in fwd_packets if p["flags"] and "U" in p["flags"]),
            "Bwd URG Flags": sum(1 for p in bwd_packets if p["flags"] and "U" in p["flags"]),
            "Fwd Header Length": sum(p["header_length"] for p in fwd_packets),
            "Bwd Header Length": sum(p["header_length"] for p in bwd_packets),
            "Fwd Packets/s": len(fwd_packets) / (flow_duration if flow_duration > 0 else 1),
            "Bwd Packets/s": len(bwd_packets) / (flow_duration if flow_duration > 0 else 1),
            "Min Packet Length": min((p["packet_size"] for p in flow_packets), default=0),
            "Max Packet Length": max((p["packet_size"] for p in flow_packets), default=0),
            "Packet Length Mean": np.mean([p["packet_size"] for p in flow_packets]) if flow_packets else 0,
            "Packet Length Std": np.std([p["packet_size"] for p in flow_packets]) if flow_packets else 0,
            "Packet Length Variance": np.var([p["packet_size"] for p in flow_packets]) if flow_packets else 0,
            "FIN Flag Count": sum(1 for p in flow_packets if p["flags"] and "F" in p["flags"]),
            "SYN Flag Count": sum(1 for p in flow_packets if p["flags"] and "S" in p["flags"]),
            "RST Flag Count": sum(1 for p in flow_packets if p["flags"] and "R" in p["flags"]),
            "PSH Flag Count": sum(1 for p in flow_packets if p["flags"] and "P" in p["flags"]),
            "ACK Flag Count": sum(1 for p in flow_packets if p["flags"] and "A" in p["flags"]),
            "URG Flag Count": sum(1 for p in flow_packets if p["flags"] and "U" in p["flags"]),
            "CWE Flag Count": 0,  # Placeholder
            "ECE Flag Count": 0,  # Placeholder
            "Down/Up Ratio": len(fwd_packets) / len(bwd_packets) if len(bwd_packets) > 0 else 0,
            "Average Packet Size": (sum(p["packet_size"] for p in flow_packets) /
                                    len(flow_packets)) if flow_packets else 0,
            "Avg Fwd Segment Size": (sum(p["packet_size"] for p in fwd_packets) /
                                     len(fwd_packets)) if fwd_packets else 0,
            "Avg Bwd Segment Size": (sum(p["packet_size"] for p in bwd_packets) /
                                     len(bwd_packets)) if bwd_packets else 0,
            " Fwd Header Length": sum(p["header_length"] for p in fwd_packets),
            "Fwd Avg Bytes/Bulk": 0,  # Placeholder
            "Fwd Avg Packets/Bulk": 0,  # Placeholder
            "Fwd Avg Bulk Rate": 0,  # Placeholder
            "Bwd Avg Bytes/Bulk": 0,  # Placeholder
            "Bwd Avg Packets/Bulk": 0,  # Placeholder
            "Bwd Avg Bulk Rate": 0,  # Placeholder
            "Subflow Fwd Packets": len(fwd_packets),
            "Subflow Fwd Bytes": sum(p["packet_size"] for p in fwd_packets),
            "Subflow Bwd Packets": len(bwd_packets),
            "Subflow Bwd Bytes": sum(p["packet_size"] for p in bwd_packets),
            "Init_Win_bytes_forward": 0,  # Placeholder
            "Init_Win_bytes_backward": 0,  # Placeholder
            "act_data_pkt_fwd": 0,  # Placeholder
            "min_seg_size_forward": 0,  # Placeholder
            "Active Mean": 0,  # Placeholder
            "Active Std": 0,  # Placeholder
            "Active Max": 0,  # Placeholder
            "Active Min": 0,  # Placeholder
            "Idle Mean": 0,  # Placeholder
            "Idle Std": 0,  # Placeholder
            "Idle Max": 0,  # Placeholder
            "Idle Min": 0,  # Placeholder
        }

        flow_features.append(flow)

    return pd.DataFrame(flow_features)


def packet_handler(packet):
    """
    Handle each captured packet.
    """
    features = extract_features(packet)
    if features:
        packets.append(features)


def capture_traffic(duration=10, iface=None, output_pcap="captured_traffic.pcap"):
    """
    Capture live traffic for a specified duration and save it as a PCAP file.
    """
    print(
        f"[INFO] Sniffing for {duration} seconds on interface: {iface or 'default'}")

    # Capture packets
    captured_packets = sniff(prn=packet_handler, timeout=duration, iface=iface)
    print("[INFO] Done sniffing.")

    # Save captured packets to a PCAP file
    if captured_packets:
        wrpcap(output_pcap, captured_packets)
        print(f"[INFO] Captured packets saved to {output_pcap}")

    # Process packets into flows
    if packets:
        return process_flows(packets)
    else:
        print("[WARN] No packets captured.")
        return pd.DataFrame()


def main():
    df = capture_traffic(duration=60, iface='en0')
    if df.empty:
        return

    model_path = os.path.join("models", "xgboost_model.pkl")
    if not os.path.exists(model_path):
        print(
            "[ERROR] Model not found. Please train it first using train-anomaly-model.")
        return

    model = joblib.load(model_path)
    predictions = model.predict(df[["Destination Port",
                                   "Flow Duration",
                                    "Total Fwd Packets",
                                    "Total Backward Packets",
                                    "Total Length of Fwd Packets",
                                    "Total Length of Bwd Packets",
                                    "Fwd Packet Length Max",
                                    "Fwd Packet Length Min",
                                    "Fwd Packet Length Mean",
                                    "Fwd Packet Length Std",
                                    "Bwd Packet Length Max",
                                    "Bwd Packet Length Min",
                                    "Bwd Packet Length Mean",
                                    "Bwd Packet Length Std",
                                    "Flow Bytes/s",
                                    "Flow Packets/s",
                                    "Flow IAT Mean",
                                    "Flow IAT Std",
                                    "Flow IAT Max",
                                    "Flow IAT Min",
                                    "Fwd IAT Total",
                                    "Fwd IAT Mean",
                                    "Fwd IAT Std",
                                    "Fwd IAT Max",
                                    "Fwd IAT Min",
                                    "Bwd IAT Total",
                                    "Bwd IAT Mean",
                                    "Bwd IAT Std",
                                    "Bwd IAT Max",
                                    "Bwd IAT Min",
                                    "Fwd PSH Flags",
                                    "Bwd PSH Flags",
                                    "Fwd URG Flags",
                                    "Bwd URG Flags",
                                    "Fwd Header Length",
                                    "Bwd Header Length",
                                    "Fwd Packets/s",
                                    "Bwd Packets/s",
                                    "Min Packet Length",
                                    "Max Packet Length",
                                    "Packet Length Mean",
                                    "Packet Length Std",
                                    "Packet Length Variance",
                                    "FIN Flag Count",
                                    "SYN Flag Count",
                                    "RST Flag Count",
                                    "PSH Flag Count",
                                    "ACK Flag Count",
                                    "URG Flag Count",
                                    "CWE Flag Count",
                                    "ECE Flag Count",
                                    "Down/Up Ratio",
                                    "Average Packet Size",
                                    "Avg Fwd Segment Size",
                                    "Avg Bwd Segment Size",
                                    " Fwd Header Length",
                                    "Fwd Avg Bytes/Bulk",
                                    "Fwd Avg Packets/Bulk",
                                    "Fwd Avg Bulk Rate",
                                    "Bwd Avg Bytes/Bulk",
                                    "Bwd Avg Packets/Bulk",
                                    "Bwd Avg Bulk Rate",
                                    "Subflow Fwd Packets",
                                    "Subflow Fwd Bytes",
                                    "Subflow Bwd Packets",
                                    "Subflow Bwd Bytes",
                                    "Init_Win_bytes_forward",
                                    "Init_Win_bytes_backward",
                                    "act_data_pkt_fwd",
                                    "min_seg_size_forward",
                                    "Active Mean",
                                    "Active Std",
                                    "Active Max",
                                    "Active Min",
                                    "Idle Mean",
                                    "Idle Std",
                                    "Idle Max",
                                    "Idle Min"
                                    ]])
    df["label"] = ["BENIGN" if p == 0 else "MALICIOUS" for p in predictions]

    print("[RESULT] Live Traffic Prediction Results:")
    print(df[["Source IP",
             "Destination IP",
              "Source Port",
              "Destination Port",
              "Protocol",
              "label"
              ]])


if __name__ == "__main__":
    main()
