"""
NetScope — HTTP/HTTPS Traffic Analyzer
Flask Web Backend: Routing, File Uploads, Analysis Caching, API Endpoints, and Reports.
"""
import glob
import os
import sys
import uuid
import datetime
from typing import Dict, Any, Optional, List
from flask import Flask, render_template, request, jsonify, send_file, url_for
from werkzeug.utils import secure_filename

from traffic_analyzer import TrafficAnalyzer, TSharkDetector, PacketRecord

# Application Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
SAMPLE_FOLDER = os.path.join(BASE_DIR, "NetScope_HTTP_HTTPS_Analyzer", "sample_data")
ALLOWED_EXTENSIONS = {"csv", "pcap", "pcapng", "cap"}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(SAMPLE_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SECRET_KEY"] = os.urandom(24).hex()

analyzer = TrafficAnalyzer()

# Analysis State Cache: stores current or multi-session analyses
analysis_store: Dict[str, Dict[str, Any]] = {}
active_analysis_id: Optional[str] = None
def load_saved_college_capture():
    global active_analysis_id

    capture_path = os.path.join(
        SAMPLE_FOLDER,
       "college_traffic.pcapng"
    )

    if not os.path.exists(capture_path):
        print("[Startup] College capture not found. Sample data can be loaded manually.")
        return

    try:
        records = analyzer.parse_file(capture_path)
        stats = analyzer.calculate_statistics(records)

        analysis_id = str(uuid.uuid4())
        analysis_store[analysis_id] = {
            "id": analysis_id,
            "filename": "college_traffic.pcapng",
            "filepath": capture_path,
            "is_sample": False,
            "records": records,
            "stats": stats,
            "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        active_analysis_id = analysis_id

        print(f"[Startup] College capture loaded: {stats['total_packets']} packets.")

    except Exception as e:
        print(f"[Startup] Could not load college capture: {e}")

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_current_analysis() -> Optional[Dict[str, Any]]:
    global active_analysis_id
    if active_analysis_id and active_analysis_id in analysis_store:
        return analysis_store[active_analysis_id]
    return None


# ---------------------------------------------------------
# Web Page Route
# ---------------------------------------------------------
@app.route("/")
def index():
    tshark_status = TSharkDetector.get_status()
    current = get_current_analysis()
    return render_template(
        "index.html",
        tshark=tshark_status,
        has_analysis=(current is not None),
        is_sample=(current.get("is_sample", False) if current else False),
        filename=(current.get("filename", "") if current else "")
    )


# ---------------------------------------------------------
# System Status API
# ---------------------------------------------------------
@app.route("/api/status", methods=["GET"])
def system_status():
    tshark_status = TSharkDetector.get_status()
    current = get_current_analysis()
    return jsonify({
        "success": True,
        "tshark": tshark_status,
        "active_analysis": {
            "loaded": (current is not None),
            "id": active_analysis_id,
            "filename": current.get("filename") if current else None,
            "is_sample": current.get("is_sample", False) if current else False,
            "total_packets": current["stats"]["total_packets"] if current else 0,
            "analyzed_at": current.get("analyzed_at") if current else None
        },
        "allowed_extensions": list(ALLOWED_EXTENSIONS),
        "max_size_mb": MAX_CONTENT_LENGTH // (1024 * 1024)
    })


# ---------------------------------------------------------
# File Upload API
# ---------------------------------------------------------
@app.route("/api/upload", methods=["POST"])
def upload_file():
    global active_analysis_id
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file part in upload request."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected for analysis."}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "success": False,
            "error": f"Invalid file format '{file.filename}'. Allowed types: .csv, .pcap, .pcapng"
        }), 400

    original_name = file.filename
    clean_name = secure_filename(original_name)
    file_id = str(uuid.uuid4())[:8]
    saved_filename = f"{file_id}_{clean_name}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_filename)

    try:
        file.save(save_path)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to save upload: {str(e)}"}), 500

    # Parse and analyze
    try:
        records = analyzer.parse_file(save_path)
        stats = analyzer.calculate_statistics(records)
    except Exception as e:
        # Clean up temporary upload on failure
        if os.path.exists(save_path):
            try: os.remove(save_path)
            except OSError: pass
        return jsonify({
            "success": False,
            "error": f"Error parsing capture file: {str(e)}"
        }), 422

    # Store analysis result
    analysis_id = str(uuid.uuid4())
    analysis_store[analysis_id] = {
        "id": analysis_id,
        "filename": original_name,
        "filepath": save_path,
        "is_sample": False,
        "records": records,
        "stats": stats,
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    active_analysis_id = analysis_id

    return jsonify({
        "success": True,
        "analysis_id": analysis_id,
        "filename": original_name,
        "is_sample": False,
        "stats": stats,
        "message": f"Successfully parsed and analyzed {stats['total_packets']} packets."
    })


# ---------------------------------------------------------
# Load Sample Data API
# ---------------------------------------------------------
@app.route("/api/load-sample", methods=["POST"])
def load_sample():
    global active_analysis_id
    req_format = request.json.get("format", "csv").lower() if request.is_json else "csv"

    sample_filename = "sample_traffic.csv" if req_format == "csv" else "sample_traffic.pcap"
    sample_path = os.path.join(SAMPLE_FOLDER, sample_filename)

    if not os.path.exists(sample_path):
        return jsonify({"success": False, "error": f"Sample dataset '{sample_filename}' not found."}), 404

    try:
        records = analyzer.parse_file(sample_path)
        stats = analyzer.calculate_statistics(records)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to analyze sample data: {str(e)}"}), 500

    analysis_id = str(uuid.uuid4())
    analysis_store[analysis_id] = {
        "id": analysis_id,
        "filename": f"{sample_filename} (Sample Dataset)",
        "filepath": sample_path,
        "is_sample": True,
        "records": records,
        "stats": stats,
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    active_analysis_id = analysis_id

    return jsonify({
        "success": True,
        "analysis_id": analysis_id,
        "filename": f"{sample_filename} (Sample Dataset)",
        "is_sample": True,
        "stats": stats,
        "message": f"Loaded demo dataset '{sample_filename}' ({stats['total_packets']} packets)."
    })


# ---------------------------------------------------------
# Statistics API
# ---------------------------------------------------------
@app.route("/api/statistics", methods=["GET"])
def get_statistics():
    current = get_current_analysis()
    if not current:
        return jsonify({"success": False, "error": "No traffic analysis currently loaded."}), 404

    return jsonify({
        "success": True,
        "filename": current["filename"],
        "is_sample": current["is_sample"],
        "analyzed_at": current["analyzed_at"],
        "stats": current["stats"]
    })


# ---------------------------------------------------------
# Packet Explorer API (Pagination, Filtering, Sorting)
# ---------------------------------------------------------
@app.route("/api/packets", methods=["GET"])
def get_packets():
    current = get_current_analysis()
    if not current:
        return jsonify({
            "success": True,
            "packets": [],
            "total_packets": 0,
            "total_filtered": 0,
            "page": 1,
            "page_size": 25,
            "total_pages": 0
        })

    records: List[PacketRecord] = current["records"]
    total_packets = len(records)

    # Filtering parameters
    search_query = request.args.get("search", "").strip().lower()
    protocol_filter = request.args.get("protocol", "").strip().upper()
    category_filter = request.args.get("category", "").strip()
    port_filter = request.args.get("port", "").strip()

    filtered = records
    if protocol_filter and protocol_filter != "ALL":
        filtered = [p for p in filtered if p.protocol.upper() == protocol_filter]

    if category_filter and category_filter != "ALL":
        filtered = [p for p in filtered if p.traffic_category == category_filter]

    if port_filter and port_filter.isdigit():
        p_num = int(port_filter)
        filtered = [p for p in filtered if p.src_port == p_num or p.dst_port == p_num]

    if search_query:
        def match_search(p: PacketRecord) -> bool:
            return (
                search_query in str(p.no) or
                search_query in p.src_ip.lower() or
                search_query in p.dst_ip.lower() or
                search_query in p.protocol.lower() or
                search_query in (p.info or "").lower() or
                search_query in (p.tcp_flags or "").lower() or
                search_query in (p.tls_sni or "").lower() or
                (p.src_port is not None and search_query in str(p.src_port)) or
                (p.dst_port is not None and search_query in str(p.dst_port))
            )
        filtered = [p for p in filtered if match_search(p)]

    total_filtered = len(filtered)

    # Sorting
    sort_by = request.args.get("sort_by", "no")
    sort_dir = request.args.get("sort_dir", "asc").lower()
    reverse = (sort_dir == "desc")

    def sort_key(p: PacketRecord):
        val = getattr(p, sort_by, None)
        if val is None:
            return -1 if reverse else float("inf")
        return val

    try:
        filtered = sorted(filtered, key=sort_key, reverse=reverse)
    except Exception:
        pass

    # Pagination
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = max(5, min(200, int(request.args.get("page_size", 25))))
    except ValueError:
        page = 1
        page_size = 25

    total_pages = max(1, (total_filtered + page_size - 1) // page_size) if total_filtered > 0 else 0
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_items = [p.to_dict() for p in filtered[start_idx:end_idx]]

    return jsonify({
        "success": True,
        "packets": page_items,
        "total_packets": total_packets,
        "total_filtered": total_filtered,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    })


# ---------------------------------------------------------
# Single Packet Details API
# ---------------------------------------------------------
@app.route("/api/packet/<int:packet_no>", methods=["GET"])
def get_packet_detail(packet_no: int):
    current = get_current_analysis()
    if not current:
        return jsonify({"success": False, "error": "No analysis loaded."}), 404

    record = next((p for p in current["records"] if p.no == packet_no), None)
    if not record:
        return jsonify({"success": False, "error": f"Packet #{packet_no} not found."}), 404

    return jsonify({
        "success": True,
        "packet": record.to_dict()
    })


# ---------------------------------------------------------
# Export APIs
# ---------------------------------------------------------
@app.route("/api/export/<string:export_type>", methods=["GET"])
def export_report(export_type: str):
    current = get_current_analysis()
    if not current:
        return jsonify({"success": False, "error": "No analysis available to export."}), 404

    analysis_id = current["id"]
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if export_type == "csv":
        out_filename = f"netscope_analyzed_packets_{timestamp_str}.csv"
        out_path = os.path.join(app.config["OUTPUT_FOLDER"], f"{analysis_id}_packets.csv")
        analyzer.export_analyzed_csv(current["records"], out_path)
        return send_file(out_path, as_attachment=True, download_name=out_filename)

    elif export_type == "summary-json":
        out_filename = f"netscope_statistics_{timestamp_str}.json"
        out_path = os.path.join(app.config["OUTPUT_FOLDER"], f"{analysis_id}_stats.json")
        analyzer.export_statistics_json(current["stats"], out_path)
        return send_file(out_path, as_attachment=True, download_name=out_filename)

    elif export_type == "summary-csv":
        out_filename = f"netscope_summary_stats_{timestamp_str}.csv"
        out_path = os.path.join(app.config["OUTPUT_FOLDER"], f"{analysis_id}_summary.csv")
        analyzer.export_statistics_csv(current["stats"], out_path)
        return send_file(out_path, as_attachment=True, download_name=out_filename)

    else:
        return jsonify({"success": False, "error": f"Unknown export type '{export_type}'."}), 400


# ---------------------------------------------------------
# Clear Current Analysis API
# ---------------------------------------------------------
@app.route("/api/clear", methods=["POST"])
def clear_analysis():
    global active_analysis_id
    active_analysis_id = None
    return jsonify({"success": True, "message": "Cleared active analysis."})


# ---------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "success": False,
        "error": f"Uploaded file exceeds maximum allowed size of {MAX_CONTENT_LENGTH // (1024*1024)} MB."
    }), 413


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "API endpoint not found."}), 404
    return render_template("index.html", tshark=TSharkDetector.get_status(), has_analysis=False), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error. Check server logs."
    }), 500

load_saved_college_capture()
if __name__ == "__main__":
    print("=" * 60)
    print(" NetScope — HTTP/HTTPS Traffic Analyzer")
    print(" Local Development Server Starting...")
    
    status = TSharkDetector.get_status()
    print(f" [TShark Engine] {status['message']}")
    print(" URL: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
