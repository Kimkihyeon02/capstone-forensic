import json
import os
from datetime import datetime, timezone

TARGET_LOGS = ["conn.log", "dns.log", "ssl.log", "http.log", "files.log", "weird.log"]

def parse_zeek_log(filepath):
    fields = []
    records = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                values = line.split("\t")
                if len(values) == len(fields):
                    records.append(dict(zip(fields, values)))
    return records

def is_internal(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")

def get_direction(src_ip, dst_ip):
    src_int = is_internal(src_ip)
    dst_int = is_internal(dst_ip)
    if src_int and dst_int:
        return "internal_to_internal"
    elif src_int and not dst_int:
        return "internal_to_external"
    elif not src_int and dst_int:
        return "external_to_internal"
    else:
        return "external_to_external"

def ts_to_datetime(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
    except:
        return ""

def safe_int(val):
    try:
        return int(val) if val and val != "-" else None
    except:
        return None

def safe_float(val):
    try:
        return float(val) if val and val != "-" else None
    except:
        return None

def safe_bool(val):
    if val == "T":
        return True
    elif val == "F":
        return False
    return None

def normalize_flow(record, flow_id):
    src_ip = record.get("id.orig_h", "")
    dst_ip = record.get("id.resp_h", "")
    ts = record.get("ts", "")

    return {
        "flow_id": f"flow_{flow_id:06d}",
        "uid": record.get("uid", None),
        "ts": safe_float(ts),
        "datetime": ts_to_datetime(ts),
        "src_ip": src_ip,
        "src_port": safe_int(record.get("id.orig_p")),
        "dst_ip": dst_ip,
        "dst_port": safe_int(record.get("id.resp_p")),
        "proto": record.get("proto", "unknown"),
        "service": record.get("service", None) if record.get("service", "-") != "-" else None,
        "duration": safe_float(record.get("duration")),
        "orig_bytes": safe_int(record.get("orig_bytes")),
        "resp_bytes": safe_int(record.get("resp_bytes")),
        "total_bytes": (safe_int(record.get("orig_bytes")) or 0) + (safe_int(record.get("resp_bytes")) or 0),
        "orig_pkts": safe_int(record.get("orig_pkts")),
        "resp_pkts": safe_int(record.get("resp_pkts")),
        "total_pkts": (safe_int(record.get("orig_pkts")) or 0) + (safe_int(record.get("resp_pkts")) or 0),
        "conn_state": record.get("conn_state", None) if record.get("conn_state", "-") != "-" else None,
        "local_orig": safe_bool(record.get("local_orig")),
        "local_resp": safe_bool(record.get("local_resp")),
        "missed_bytes": safe_int(record.get("missed_bytes")),
        "history": record.get("history", None) if record.get("history", "-") != "-" else None,
        "tunnel_parents": [],
        "is_internal_src": is_internal(src_ip),
        "is_internal_dst": is_internal(dst_ip),
        "is_external_src": not is_internal(src_ip),
        "is_external_dst": not is_internal(dst_ip),
        "direction": get_direction(src_ip, dst_ip),
        "community_id": record.get("community_id", None) if record.get("community_id", "-") != "-" else None,
        "raw": record
    }

def get_event_type(log_name):
    mapping = {
        "dns.log": "dns",
        "http.log": "http",
        "ssl.log": "tls",
        "files.log": "file",
        "weird.log": "weird"
    }
    return mapping.get(log_name, "unknown")

def get_summary(log_name, record):
    if log_name == "dns.log":
        query = record.get("query", "-")
        return f"DNS 쿼리: {query}"
    elif log_name == "http.log":
        method = record.get("method", "-")
        host = record.get("host", "-")
        uri = record.get("uri", "-")
        return f"HTTP {method} {host}{uri}"
    elif log_name == "ssl.log":
        server_name = record.get("server_name", "-")
        version = record.get("version", "-")
        return f"TLS 연결: {server_name} ({version})"
    elif log_name == "files.log":
        mime = record.get("mime_type", "-")
        filename = record.get("filename", "-")
        return f"파일 전송: {filename} ({mime})"
    elif log_name == "weird.log":
        name = record.get("name", "-")
        return f"Zeek 비정상 이벤트: {name}"
    return ""

def normalize_event(log_name, record, event_id):
    src_ip = record.get("id.orig_h", None)
    dst_ip = record.get("id.resp_h", None)
    ts = record.get("ts", "")

    return {
        "event_id": f"event_{event_id:06d}",
        "uid": record.get("uid", None),
        "fuid": record.get("fuid", None),
        "ts": safe_float(ts),
        "datetime": ts_to_datetime(ts),
        "event_type": get_event_type(log_name),
        "log_source": log_name,
        "src_ip": src_ip,
        "src_port": safe_int(record.get("id.orig_p")),
        "dst_ip": dst_ip,
        "dst_port": safe_int(record.get("id.resp_p")),
        "proto": record.get("proto", None) if record.get("proto", "-") != "-" else None,
        "service": record.get("service", None) if record.get("service", "-") != "-" else None,
        "summary": get_summary(log_name, record),
        "payload": {},
        "raw": record
    }

def process_logs(log_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    # conn.log → flow 스키마
    conn_path = os.path.join(log_dir, "conn.log")
    if os.path.exists(conn_path):
        print("[PROCESSING] conn.log → flow 스키마")
        records = parse_zeek_log(conn_path)
        normalized = [normalize_flow(r, i+1) for i, r in enumerate(records)]
        output_path = os.path.join(output_dir, "flows.json")
        with open(output_path, "w") as f:
            json.dump(normalized, f, indent=2, ensure_ascii=False)
        print(f"[DONE] conn.log → {len(normalized)}개 flow 저장")
    else:
        print("[SKIP] conn.log 없음")

    # 나머지 로그 → event 스키마
    event_logs = ["dns.log", "ssl.log", "http.log", "files.log", "weird.log"]
    all_events = []
    event_counter = 1
    for log_name in event_logs:
        log_path = os.path.join(log_dir, log_name)
        if not os.path.exists(log_path):
            print(f"[SKIP] {log_name} 없음")
            continue
        print(f"[PROCESSING] {log_name} → event 스키마")
        records = parse_zeek_log(log_path)
        for r in records:
            all_events.append(normalize_event(log_name, r, event_counter))
            event_counter += 1
        print(f"[DONE] {log_name} → {len(records)}개 이벤트")

    output_path = os.path.join(output_dir, "events.json")
    with open(output_path, "w") as f:
        json.dump(all_events, f, indent=2, ensure_ascii=False)
    print(f"[DONE] 전체 이벤트 → {len(all_events)}개 events.json 저장")

if __name__ == "__main__":
    LOG_DIR = "/home/test/capstone/zeek_logs"
    OUTPUT_DIR = "/home/test/capstone/output"
    process_logs(LOG_DIR, OUTPUT_DIR)