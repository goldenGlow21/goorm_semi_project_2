import json
import os
import threading

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), "../scan_logs.json")
SERVICE_LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), "../service_logs.json")
log_lock = threading.Lock()  # 파일 접근 동시성을 위한 Lock 객체

def initialize_log_file(log_path):
    """
    로그 파일이 없을 경우 초기화
    """
    if not os.path.exists(log_path):
        with log_lock:  # 파일 쓰기 작업에 Lock 적용
            with open(log_path, "w") as log_file:
                json.dump([], log_file)

def add_scan_log(entry):
    """
    스캔 결과를 로그 파일에 추가
    :param entry: 스캔 결과 딕셔너리
    """
    initialize_log_file(LOG_FILE_PATH)

    # 로그 형식 변환
    log_entry = {
        "ip": entry.get("ip"),
        "open": entry.get("open", []),
        "open_or_filtered": entry.get("open_or_filtered", []),
        "scan_type": entry.get("scan_type"),
        "scan_time": entry.get("scan_time"),
    }

    try:
        with log_lock:  # 파일 읽기/쓰기 작업 보호
            with open(LOG_FILE_PATH, "r") as log_file:
                logs = json.load(log_file)
    except json.JSONDecodeError:
        logs = []

    logs.append(log_entry)

    with open(LOG_FILE_PATH, "w") as log_file:
        json.dump(logs, log_file, indent=4, separators=(",", ": "))

def add_service_log(entry):
    """
    서비스/OS 탐지 결과를 별도 로그 파일에 추가
    :param entry: 서비스/OS 탐지 결과 딕셔너리
    """
    initialize_log_file(SERVICE_LOG_FILE_PATH)

    # 로그 형식 변환
    log_entry = {
        "port": entry.get("port", []),
        "service": entry.get("service", []),
        "version": entry.get("version"),
        "cves": entry.get("cves"),
        "info": entry.get("info"),
    }

    try:
        with log_lock:  # 파일 읽기/쓰기 작업 보호
            with open(SERVICE_LOG_FILE_PATH, "r") as log_file:
                logs = json.load(log_file)
    except json.JSONDecodeError:
        logs = []

    logs.append(log_entry)

    with open(SERVICE_LOG_FILE_PATH, "w") as log_file:
        json.dump(logs, log_file, indent=4, separators=(",", ": "))

def get_scan_logs():
    """
    scan_logs.json에서 모든 스캔 기록을 반환
    :return: 스캔 기록 리스트
    """
    initialize_log_file(LOG_FILE_PATH)
    try:
        with log_lock:  # 파일 읽기 작업 보호
            with open(LOG_FILE_PATH, "r") as log_file:
                logs = json.load(log_file)
    except json.JSONDecodeError:
        logs = []
    return logs

def get_service_logs():
    """
    service_logs.json에서 모든 서비스/OS 탐지 기록을 반환
    :return: 서비스/OS 탐지 기록 리스트
    """
    initialize_log_file(SERVICE_LOG_FILE_PATH)
    try:
        with log_lock:  # 파일 읽기 작업 보호
            with open(SERVICE_LOG_FILE_PATH, "r") as log_file:
                logs = json.load(log_file)
    except json.JSONDecodeError:
        logs = []
    return logs