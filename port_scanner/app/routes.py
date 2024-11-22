from flask import Blueprint, render_template, request, jsonify
from app.scanner import scan_ports  # C 모듈 연동 코드

bp = Blueprint('main', __name__)

@bp.route("/")
def home():
    return render_template("index.html")

@bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_ip = data.get("ip")
    ports = data.get("ports", [])

    if not target_ip or not ports:
        return jsonify({"error": "IP address and port list are required"}), 400

    result = scan_ports(target_ip, ports)
    return jsonify(result)
