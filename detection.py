import json
import os
from collections import defaultdict

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def is_internal(ip):
    if not ip:
        return False
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")

# =====================
# 휴리스틱 탐지 함수들
# =====================

def detect_beaconing(flows, start_counter=1):
    detections = []
    group = defaultdict(list)

    for flow in flows:
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")
        duration = flow.get("duration") or 0
        orig_pkts = flow.get("orig_pkts") or 0

        if 0 < duration < 1 and orig_pkts <= 5:
            group[(src, dst)].append(flow)

    det_counter = start_counter
    for (src, dst), group_flows in group.items():
        if len(group_flows) >= 3:
            sample_ids = [f["flow_id"] for f in group_flows[:5]]
            detections.append({
                "detection_id": f"det_{det_counter:06d}",
                "type": "heuristic",
                "severity": "medium",
                "title": f"Beaconing 의심: {src} → {dst} 반복 연결",
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": group_flows[0].get("dst_port"),
                "proto": group_flows[0].get("proto"),
                "evidence_event_ids": sample_ids,
                "evidence_count": len(group_flows),
                "tags": ["beaconing_candidate", "suspicious_connection"],
                "reason": f"{src}에서 {dst}로 짧은 연결이 {len(group_flows)}회 반복됨"
            })
            det_counter += 1

    return detections, det_counter

def detect_port_scan(flows, start_counter):
    detections = []
    group = defaultdict(list)

    for flow in flows:
        src = flow.get("src_ip", "")
        conn_state = flow.get("conn_state", "")
        orig_pkts = flow.get("orig_pkts") or 0

        if orig_pkts <= 2 and conn_state in ["S0", "REJ"]:
            group[src].append(flow)

    det_counter = start_counter
    for src, group_flows in group.items():
        if len(group_flows) >= 5:
            sample_ids = [f["flow_id"] for f in group_flows[:5]]
            detections.append({
                "detection_id": f"det_{det_counter:06d}",
                "type": "heuristic",
                "severity": "medium",
                "title": f"Port Scan 의심: {src}에서 다수 포트 연결 시도",
                "src_ip": src,
                "dst_ip": group_flows[0].get("dst_ip"),
                "dst_port": None,
                "proto": group_flows[0].get("proto"),
                "evidence_event_ids": sample_ids,
                "evidence_count": len(group_flows),
                "tags": ["port_scan_candidate", "reconnaissance"],
                "reason": f"{src}에서 연결 실패 상태로 {len(group_flows)}개 포트 접근 시도"
            })
            det_counter += 1

    return detections, det_counter

def detect_large_transfer(flows, start_counter):
    detections = []
    det_counter = start_counter

    for flow in flows:
        orig_bytes = flow.get("orig_bytes") or 0
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")

        if orig_bytes > 1000000:
            detections.append({
                "detection_id": f"det_{det_counter:06d}",
                "type": "heuristic",
                "severity": "medium",
                "title": f"대용량 전송 의심: {src} → {dst}",
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": flow.get("dst_port"),
                "proto": flow.get("proto"),
                "evidence_event_ids": [flow["flow_id"]],
                "evidence_count": 1,
                "tags": ["data_exfiltration_candidate", "large_transfer"],
                "reason": f"{orig_bytes // 1024}KB 대용량 데이터 전송 감지"
            })
            det_counter += 1

    return detections, det_counter

def detect_nxdomain_burst(events, start_counter):
    detections = []
    group = defaultdict(list)

    for event in events:
        if event.get("event_type") != "dns":
            continue
        raw = event.get("raw", {})
        if raw.get("rcode_name") == "NXDOMAIN":
            src = event.get("src_ip", "")
            group[src].append(event)

    det_counter = start_counter
    for src, group_events in group.items():
        if len(group_events) >= 5:
            sample_ids = [e["event_id"] for e in group_events[:5]]
            detections.append({
                "detection_id": f"det_{det_counter:06d}",
                "type": "heuristic",
                "severity": "medium",
                "title": f"NXDOMAIN 다수 발생: {src}",
                "src_ip": src,
                "dst_ip": None,
                "dst_port": 53,
                "proto": "udp",
                "evidence_event_ids": sample_ids,
                "evidence_count": len(group_events),
                "tags": ["dns_anomaly", "nxdomain_burst", "possible_dga"],
                "reason": f"{src}에서 NXDOMAIN {len(group_events)}건 발생, DGA 의심"
            })
            det_counter += 1

    return detections, det_counter

def detect_suricata_alerts(alerts, start_counter):
    detections = []
    det_counter = start_counter

    for alert in alerts:
        severity = alert.get("severity", "low")
        detections.append({
            "detection_id": f"det_{det_counter:06d}",
            "type": "suricata",
            "severity": severity,
            "title": alert.get("summary", "Suricata Alert"),
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "dst_port": alert.get("dst_port"),
            "proto": alert.get("proto"),
            "evidence_event_ids": [alert["event_id"]],
            "evidence_count": 1,
            "tags": alert.get("tags", []),
            "reason": alert.get("summary", "")
        })
        det_counter += 1

    return detections, det_counter

def generate_detections(output_dir):
    flows_path = os.path.join(output_dir, "flows.json")
    events_path = os.path.join(output_dir, "events.json")
    alerts_path = os.path.join(output_dir, "suricata_alerts.json")

    flows = load_json(flows_path) if os.path.exists(flows_path) else []
    events = load_json(events_path) if os.path.exists(events_path) else []
    alerts = load_json(alerts_path) if os.path.exists(alerts_path) else []

    all_detections = []
    counter = 1

    d, counter = detect_beaconing(flows, counter)
    all_detections.extend(d)
    print(f"[DETECT] Beaconing 의심: {len(d)}개")

    d, counter = detect_port_scan(flows, counter)
    all_detections.extend(d)
    print(f"[DETECT] Port Scan 의심: {len(d)}개")

    d, counter = detect_large_transfer(flows, counter)
    all_detections.extend(d)
    print(f"[DETECT] 대용량 전송 의심: {len(d)}개")

    d, counter = detect_nxdomain_burst(events, counter)
    all_detections.extend(d)
    print(f"[DETECT] NXDOMAIN Burst 의심: {len(d)}개")

    d, counter = detect_suricata_alerts(alerts, counter)
    all_detections.extend(d)
    print(f"[DETECT] Suricata Alert: {len(d)}개")

    output_path = os.path.join(output_dir, "detections.json")
    with open(output_path, "w") as f:
        json.dump(all_detections, f, indent=2, ensure_ascii=False)

    print(f"\n[DONE] 총 {len(all_detections)}개 Detection 저장 → detections.json")

if __name__ == "__main__":
    OUTPUT_DIR = "/home/test/capstone/output"
    generate_detections(OUTPUT_DIR)