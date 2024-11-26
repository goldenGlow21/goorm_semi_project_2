from flask import Blueprint, request, jsonify, render_template
from app.scanner import scan_ports
from app.log_manager import add_scan_log, get_scan_logs
from datetime import datetime

bp = Blueprint("main", __name__)

@bp.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_ip = data.get("target_ip")
    scan_type = data.get("scan_type")
    start_port = data.get("target_start_port", 1)
    end_port = data.get("target_end_port", 65535)

    # 유효성 검사
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({"error": "Invalid or missing IP address"}), 400
    if scan_type not in ["tcp_connect", "tcp_syn", "udp", "xmas", "null", "ack"]:
        return jsonify({"error": f"Unsupported scan type: {scan_type}"}), 400
    try:
        start_port = int(start_port)
        end_port = int(end_port)
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({"error": "Invalid port range"}), 400

    ports = range(start_port, end_port + 1)

    # 스캔 수행
    try:
        open_ports, open_or_filtered_ports = scan_ports(target_ip, ports, scan_type)
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    # 결과 기록
    scan_time = datetime.utcnow().isoformat() + "Z"
    log_entry = {
        "ip": target_ip,
        "open": open_ports,
        "open_or_filtered": open_or_filtered_ports,
        "scan_type": scan_type,
        "scan_time": scan_time,
    }
    add_scan_log(log_entry)

    # 응답 생성
    return jsonify(log_entry)

@bp.route("/logs", methods=["GET"])
def logs():
    """
    스캔 기록 반환
    """
    logs = get_scan_logs()
    return jsonify(logs)
