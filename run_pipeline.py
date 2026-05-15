import subprocess
import os
import sys
import json
from zeek_parser import process_logs
from suricata_parser import process_suricata
from detection import generate_detections

def run_zeek(pcap_path, log_dir):
    print(f"[ZEEK] PCAP 분석 시작: {pcap_path}")
    os.makedirs(log_dir, exist_ok=True)
    result = subprocess.run(
        ["zeek", "-r", pcap_path],
        cwd=log_dir,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"[ZEEK ERROR] {result.stderr}")
        sys.exit(1)
    print(f"[ZEEK] 완료 → 로그 생성됨")

def run_suricata(pcap_path, suricata_log_dir):
    print(f"[SURICATA] PCAP 분석 시작: {pcap_path}")
    os.makedirs(suricata_log_dir, exist_ok=True)
    result = subprocess.run(
        ["suricata", "-r", pcap_path, "-l", suricata_log_dir, "-S", "/var/lib/suricata/rules/suricata.rules"],
        capture_output=True,
        text=True
    )
    print(f"[SURICATA] 완료 → eve.json 생성됨")

def main(pcap_path):
    BASE_DIR = "/home/test/capstone"
    LOG_DIR = os.path.join(BASE_DIR, "zeek_logs")
    SURICATA_LOG_DIR = os.path.join(BASE_DIR, "suricata_logs")
    OUTPUT_DIR = os.path.join(BASE_DIR, "output")

    # 1. Zeek 실행
    run_zeek(pcap_path, LOG_DIR)

    # 2. Suricata 실행
    run_suricata(pcap_path, SURICATA_LOG_DIR)

    # 3. Zeek 파서 실행
    print(f"[PARSER] Zeek 로그 → JSON 변환")
    process_logs(LOG_DIR, OUTPUT_DIR)

    # 4. Suricata 파서 실행
    print(f"[PARSER] Suricata alert → JSON 변환")
    eve_path = os.path.join(SURICATA_LOG_DIR, "eve.json")
    process_suricata(eve_path, OUTPUT_DIR)

    # 5. Detection 생성
    print(f"[DETECTION] Detection 생성 중")
    generate_detections(OUTPUT_DIR)

    print("\n=============================")
    print("[DONE] 전체 파이프라인 완료!")
    print(f"output 폴더 확인: {OUTPUT_DIR}")
    print("  - flows.json")
    print("  - events.json")
    print("  - suricata_alerts.json")
    print("  - detections.json")
    print("=============================")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python3 run_pipeline.py <pcap파일경로>")
        sys.exit(1)
    pcap_path = sys.argv[1]
    main(pcap_path)