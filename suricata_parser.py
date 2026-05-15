import json
import os
from datetime import datetime, timezone

def ts_to_datetime(ts_str):
    """Suricata timestamp 문자열 → datetime 변환"""
    try:
        # Suricata timestamp 형식: "2026-03-01T04:55:09.819008+0900"
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    except:
        return ts_str

def parse_suricata_alerts(eve_path):
    """eve.json에서 alert만 추출"""
    alerts = []
    with open(eve_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if record.get("event_type") == "alert":
                    alerts.append(record)
            except:
                continue
    return alerts

def get_severity_str(severity_int):
    """Suricata severity 숫자 → 문자열 변환"""
    if severity_int == 1:
        return "high"
    elif severity_int == 2:
        return "medium"
    else:
        return "low"

def normalize_alert(record, event_id):
    """Suricata alert → event 스키마"""
    alert = record.get("alert", {})
    http = record.get("http", {})
    dns = record.get("dns", {})
    
    timestamp = record.get("timestamp", "")
    
    # severity 변환
    severity_int = alert.get("severity", 3)
    severity = get_severity_str(severity_int)
    
    # summary
    signature = alert.get("signature", "")
    category = alert.get("category", "")
    summary = f"{signature} ({category})" if category else signature
    
    # tags
    tags = ["alert"]
    if category:
        tags.append(category.lower().replace(" ", "_"))
    if severity == "high":
        tags.append("high_severity")
    
    # payload에 상세 정보
    payload = {
        "signature_id": alert.get("signature_id"),
        "signature": signature,
        "category": category,
        "severity": severity_int,
        "action": alert.get("action", ""),
        "confidence": alert.get("metadata", {}).get("confidence", []),
    }
    
    # http 정보 있으면 추가
    if http:
        payload["http"] = {
            "hostname": http.get("hostname", ""),
            "url": http.get("url", ""),
            "method": http.get("http_method", ""),
            "status": http.get("status", "")
        }

    return {
        "event_id": f"event_s_{event_id:06d}",
        "uid": str(record.get("flow_id", "")),
        "fuid": None,
        "ts": None,
        "datetime": ts_to_datetime(timestamp),
        "event_type": "alert",
        "log_source": "suricata",
        "src_ip": record.get("src_ip", None),
        "src_port": record.get("src_port", None),
        "dst_ip": record.get("dest_ip", None),
        "dst_port": record.get("dest_port", None),
        "proto": record.get("proto", None),
        "service": record.get("app_proto", None),
        "summary": summary,
        "tags": tags,
        "severity": severity,
        "payload": payload,
        "raw": record
    }

def process_suricata(eve_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[PROCESSING] eve.json → alert 추출")
    alerts = parse_suricata_alerts(eve_path)
    print(f"[OK] {len(alerts)}개 alert 발견")
    
    normalized = [normalize_alert(r, i+1) for i, r in enumerate(alerts)]
    
    output_path = os.path.join(output_dir, "suricata_alerts.json")
    with open(output_path, "w") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)
    
    print(f"[DONE] suricata_alerts.json → {len(normalized)}개 alert 저장")

if __name__ == "__main__":
    EVE_PATH = "/home/test/capstone/suricata_logs/eve.json"
    OUTPUT_DIR = "/home/test/capstone/output"
    process_suricata(EVE_PATH, OUTPUT_DIR)