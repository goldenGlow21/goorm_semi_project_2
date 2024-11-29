from flask import Blueprint, request, jsonify, render_template
from app.scanner import scan_ports
from app.log_manager import add_scan_log, get_scan_logs
from datetime import datetime

bp = Blueprint("main", __name__)

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
    target_ip = data.get("target_ip")
    scan_type = data.get("scan_type")
    start_port = data.get("target_start_port", 1)
    end_port = data.get("target_end_port", 65535)

    # 유효성 검사
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({"error": "Invalid or missing IP address"}), 400
    if scan_type not in ["tcp_connect", "tcp_syn", "tcp_fin", "udp", "xmas", "null", "ack"]:
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
        scan_results = scan_ports(target_ip, start_port, end_port, scan_type)
        scan_results["ip"] = target_ip
        scan_results["scan_type"] = scan_type
        scan_results["scan_time"] = datetime.utcnow().isoformat() + "Z"
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    # 결과 기록
    add_scan_log(scan_results)

    # 응답 반환
    return jsonify(scan_results)

@bp.route("/logs", methods=["GET"])
def logs():
    """
    스캔 기록 반환
    """
    logs = get_scan_logs()
    return jsonify(logs)
