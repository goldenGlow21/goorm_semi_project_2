from flask import Blueprint, request, jsonify, render_template
from app.scanner import scan_ports
from app.log_manager import add_scan_log, add_service_log, get_scan_logs, get_service_logs
from datetime import datetime
from modules.common import get_ip_from_domain
import re

bp = Blueprint("main", __name__)

# 정규식으로 IPv4 주소 확인
def is_valid_ip(ip):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(ip_regex, ip) is not None

@bp.route("/", methods=["GET"])
def home():
    """
    메인 페이지 렌더링
    """
    return render_template("index.html")

@bp.route("/scan", methods=["POST"])
def scan():
    """
    포트 스캔 요청 처리
    """
    data = request.get_json()
    target_ip_or_domain = data.get("target_ip")
    scan_type = data.get("scan_type")
    start_port = data.get("target_start_port", 1)
    end_port = data.get("target_end_port", 65535)

    # 유효성 검사
    if not target_ip_or_domain or not isinstance(target_ip_or_domain, str):
        return jsonify({"error": "Invalid or missing IP address or domain"}), 400
    
    # 입력값이 IP인지 도메인인지 확인
    if is_valid_ip(target_ip_or_domain):
        target_ip = target_ip_or_domain  # IP라면 그대로 사용
    else:
        try:
            # 도메인일 경우 IP로 변환
            target_ip = get_ip_from_domain(target_ip_or_domain)
        except Exception as e:
            return jsonify({"error": f"Failed to resolve domain to IP: {str(e)}"}), 400

    if scan_type not in ["tcp_connect", "tcp_syn", "tcp_fin", "udp", "xmas", "null", "ack", "additional_info"]:
        return jsonify({"error": f"Unsupported scan type: {scan_type}"}), 400
    try:
        start_port = int(start_port)
        end_port = int(end_port)
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            raise ValueError
    except ValueError:
        return jsonify({"error": "Invalid port range"}), 400

    # 스캔 수행
    try:
        if scan_type == "additional_info":
            # CVE 정보 포함 스캔 수행
            scan_results = {}
            
            # 공통 메타데이터 추가
            scan_results["ip"] = target_ip
            scan_results["scan_type"] = scan_type
            scan_results["scan_time"] = datetime.utcnow().isoformat() + "Z"

            # CVE 정보 포함 스캔 수행
            scan_results["cves"] = scan_ports(target_ip, start_port, end_port, scan_type)

            # 결과를 service_log.json에 기록
            add_service_log(scan_results)

            return jsonify(scan_results)

        scan_results = scan_ports(target_ip, start_port, end_port, scan_type)

        # 스캔 결과를 구성
        if scan_type in ["udp", "tcp_fin", "xmas", "null"]:
            result = {
                "ip": target_ip,
                "scan_type": scan_type,
                "scan_time": datetime.utcnow().isoformat() + "Z",
                "open_or_filtered": scan_results.get("port_list", []),
            }
        else:
            result = {
                "ip": target_ip,
                "scan_type": scan_type,
                "scan_time": datetime.utcnow().isoformat() + "Z",
                "open": scan_results.get("port_list", []),
            }

        # 로그 기록
        add_scan_log(result)

    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    # 응답 반환
    return jsonify(scan_results)

@bp.route("/logs", methods=["GET"])
def logs():
    """
    스캔 기록 반환
    """
    logs = get_scan_logs()
    return jsonify(logs)

@bp.route("/service_logs", methods=["GET"])
def service_logs():
    """
    서비스/OS 탐지 기록 반환
    """
    logs = get_service_logs()
    return jsonify(logs)
