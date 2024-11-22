from flask import Blueprint, request, jsonify, render_template
from app.scanner import scan_ports

bp = Blueprint("main", __name__)

@bp.route("/", methods=["GET"])
def home():
    return render_template("index.html")

# 클라이언트에서 scan_type을 받아 scan_ports 함수에 전달
@bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_ip = data.get("ip")
    ports = data.get("ports")
    scan_type = data.get("scan_type", "tcp_connect")  # 기본값: TCP Connect - 필요시 변경

    # 잘못된 scan_type 요청 시 400 에러 반환
    if not target_ip or not ports:
        return jsonify({"error": "IP address and ports are required"}), 400

    if scan_type not in ["tcp_connect", "tcp_syn", "udp", "xmas", "ack", "null"]:
        return jsonify({"error": f"Invalid scan type: {scan_type}"}), 400

    # 스캔 실행
    result = scan_ports(target_ip, ports, scan_type)
    return jsonify(result)
