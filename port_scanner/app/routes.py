from flask import Blueprint, request, jsonify, render_template
from app.scanner import scan_ports
from datetime import datetime

bp = Blueprint("main", __name__)

@bp.route("/", methods=["GET"])
def home():
    return render_template("index.html")

# 클라이언트에서 scan_type을 받아 scan_ports 함수에 전달
@bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_ip = data.get("ip")
    scan_type = data.get("scan_type")

    # 유효성 검사
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({"error": "Invalid or missing IP address"}), 400
    if scan_type not in ["tcp_connect", "tcp_syn", "udp", "xmas", "null", "ack"]:
        return jsonify({"error": f"Unsupported scan type: {scan_type}"}), 400

    # 전체 포트 스캔 (1~65535)
    ports = range(1, 65536)

    # 스캔 수행
    results = scan_ports(target_ip, ports, scan_type)

    # 응답 생성
    response = {
        "ip": target_ip,
        "results": {
            port: {
                "protocol": scan_type,
                "status": results[port]
            } for port in results
        },
        "scan_type": scan_type,
        "scan_time": datetime.utcnow().isoformat() + "Z"
    }
    return jsonify(response)
