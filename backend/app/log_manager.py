import json
import os
import threading

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), "../scan_logs.json")
log_lock = threading.Lock()  # 파일 접근 동시성을 위한 Lock 객체

def initialize_log_file():
    """로그 파일이 없을 경우 초기화"""
    if not os.path.exists(LOG_FILE_PATH):
        with log_lock:  # 파일 쓰기 작업에 Lock 적용
            with open(LOG_FILE_PATH, "w") as log_file:
                json.dump([], log_file)

def add_scan_log(entry):
    """
    스캔 결과를 로그 파일에 추가
    :param entry: 스캔 결과 딕셔너리
    """
    initialize_log_file()
    try:
        with log_lock:  # 파일 읽기/쓰기 작업 보호
            with open(LOG_FILE_PATH, "r") as log_file:
                logs = json.load(log_file)
    except json.JSONDecodeError:
        logs = []

    logs.append(entry)

    with open(LOG_FILE_PATH, "w") as log_file:
        json.dump(logs, log_file, indent=4)

def get_scan_logs():
    """
    로그 파일에서 모든 스캔 기록을 반환
    :return: 스캔 기록 리스트
    """
    initialize_log_file()
    try:
        with log_lock:  # 파일 읽기 작업 보호
            with open(LOG_FILE_PATH, "r") as log_file:
                logs = json.load(log_file)
    except json.JSONDecodeError:
        logs = []
    return logs
