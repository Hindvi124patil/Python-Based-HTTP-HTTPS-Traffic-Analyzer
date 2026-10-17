"""
NetScope Automated Test Suite
Verifies:
1. Valid CSV input parsing
2. Handling of missing columns & edge cases
3. Empty capture input handling (prevent divide-by-zero)
4. Invalid file formats rejection
5. Protocol counts & percentage accuracy
6. Packet-size metrics (min, max, mean, median)
7. Missing port information handling (shows unavailable, does not invent)
8. Timestamp parsing and duration calculations
9. Report export functions (CSV, JSON summary, analyzed packets)
10. TShark detection status
"""

import os
import tempfile
import pytest
import pandas as pd
from traffic_analyzer import TrafficAnalyzer, TSharkDetector, clean_column_name, extract_ports_from_info


@pytest.fixture
def analyzer():
    return TrafficAnalyzer()


@pytest.fixture
def sample_csv_path():
    path = os.path.join(os.path.dirname(__file__), "..", "sample_data", "sample_traffic.csv")
    return os.path.abspath(path)


@pytest.fixture
def sample_pcap_path():
    path = os.path.join(os.path.dirname(__file__), "..", "sample_data", "sample_traffic.pcap")
    return os.path.abspath(path)


def test_tshark_detection():
    status = TSharkDetector.get_status()
    assert "available" in status
    assert "message" in status
    assert isinstance(status["available"], bool)


def test_valid_csv_parsing(analyzer, sample_csv_path):
    records = analyzer.parse_file(sample_csv_path)
    assert len(records) == 25
    first = records[0]
    assert first.no == 1
    assert first.protocol == "DNS"
    assert first.src_ip == "192.168.1.105"
    assert first.dst_ip == "8.8.8.8"
    assert first.src_port == 53120
    assert first.dst_port == 53
    assert first.length == 74


def test_missing_optional_columns(analyzer):
    """Test CSV with minimal headers (no ports, no flags, no SNI)."""
    minimal_data = [
        {"No.": 1, "Time": "1.00", "Source": "10.0.0.1", "Destination": "10.0.0.2", "Protocol": "ICMP", "Length": 64, "Info": "Echo request"},
        {"No.": 2, "Time": "1.05", "Source": "10.0.0.2", "Destination": "10.0.0.1", "Protocol": "ICMP", "Length": 64, "Info": "Echo reply"}
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        pd.DataFrame(minimal_data).to_csv(f.name, index=False)
        temp_path = f.name

    try:
        records = analyzer.parse_file(temp_path)
        assert len(records) == 2
        assert records[0].src_port is None
        assert records[0].dst_port is None
        assert records[0].tcp_flags is None
        stats = analyzer.calculate_statistics(records)
        assert stats["ports_available"] is False
        assert "Communication Ports (Source/Destination Ports not in CSV)" in stats["unavailable_fields"]
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_empty_input_handling(analyzer):
    """Test empty CSV without raising divide-by-zero errors."""
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write("No.,Time,Source,Destination,Protocol,Length,Info\n")
        temp_path = f.name

    try:
        records = analyzer.parse_file(temp_path)
        assert len(records) == 0
        stats = analyzer.calculate_statistics(records)
        assert stats["is_empty"] is True
        assert stats["total_packets"] == 0
        assert stats["total_bytes"] == 0
        assert stats["mean_packet_size"] == 0.0
        assert stats["median_packet_size"] == 0.0
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_invalid_file_type(analyzer):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("Hello World")
        temp_path = f.name

    try:
        with pytest.raises(ValueError) as excinfo:
            analyzer.parse_file(temp_path)
        assert "Unsupported file format" in str(excinfo.value)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_protocol_statistics(analyzer, sample_csv_path):
    records = analyzer.parse_file(sample_csv_path)
    stats = analyzer.calculate_statistics(records)
    # Check total packets
    assert stats["total_packets"] == 25
    # Check protocol percentages sum to ~100
    total_pct = sum(stats["protocol_percentages"].values())
    assert 99.0 <= total_pct <= 101.0
    # Check category distribution includes web protocols
    categories = stats["category_counts"]
    assert "HTTP" in categories
    assert "HTTPS/TLS" in categories
    assert "DNS" in categories
    assert "QUIC" in categories


def test_packet_size_calculations(analyzer):
    data = [
        {"No.": 1, "Length": 100, "Protocol": "TCP", "Source": "1.1.1.1", "Destination": "2.2.2.2"},
        {"No.": 2, "Length": 200, "Protocol": "TCP", "Source": "1.1.1.1", "Destination": "2.2.2.2"},
        {"No.": 3, "Length": 300, "Protocol": "TCP", "Source": "1.1.1.1", "Destination": "2.2.2.2"},
        {"No.": 4, "Length": 400, "Protocol": "TCP", "Source": "1.1.1.1", "Destination": "2.2.2.2"}
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        pd.DataFrame(data).to_csv(f.name, index=False)
        temp_path = f.name

    try:
        records = analyzer.parse_file(temp_path)
        stats = analyzer.calculate_statistics(records)
        assert stats["min_packet_size"] == 100
        assert stats["max_packet_size"] == 400
        assert stats["mean_packet_size"] == 250.0
        assert stats["median_packet_size"] == 250.0
        assert stats["total_bytes"] == 1000
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_missing_port_information(analyzer):
    """Verify that when ports are unavailable, they are marked None and not fabricated."""
    data = [
        {"No.": 1, "Length": 50, "Protocol": "ARP", "Source": "00:11:22:33:44:55", "Destination": "ff:ff:ff:ff:ff:ff", "Info": "Who has 192.168.1.1?"}
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        pd.DataFrame(data).to_csv(f.name, index=False)
        temp_path = f.name

    try:
        records = analyzer.parse_file(temp_path)
        assert records[0].src_port is None
        assert records[0].dst_port is None
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_timestamp_parsing_and_duration(analyzer):
    data = [
        {"No.": 1, "Time": "10.000", "Length": 50, "Protocol": "TCP", "Source": "1.1.1.1", "Destination": "2.2.2.2"},
        {"No.": 2, "Time": "15.500", "Length": 50, "Protocol": "TCP", "Source": "1.1.1.1", "Destination": "2.2.2.2"}
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        pd.DataFrame(data).to_csv(f.name, index=False)
        temp_path = f.name

    try:
        records = analyzer.parse_file(temp_path)
        stats = analyzer.calculate_statistics(records)
        assert stats["timestamps_available"] is True
        assert stats["duration_seconds"] == 5.5
        assert stats["duration_formatted"] == "5.50s"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_export_functionality(analyzer, sample_csv_path):
    records = analyzer.parse_file(sample_csv_path)
    stats = analyzer.calculate_statistics(records)

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_out = os.path.join(tmpdir, "packets.csv")
        json_out = os.path.join(tmpdir, "stats.json")
        summary_csv = os.path.join(tmpdir, "summary.csv")

        analyzer.export_analyzed_csv(records, csv_out)
        analyzer.export_statistics_json(stats, json_out)
        analyzer.export_statistics_csv(stats, summary_csv)

        assert os.path.isfile(csv_out)
        assert os.path.isfile(json_out)
        assert os.path.isfile(summary_csv)
        assert os.path.getsize(csv_out) > 0
        assert os.path.getsize(json_out) > 0
        assert os.path.getsize(summary_csv) > 0


def test_port_extraction_patterns():
    # Arrow pattern
    sp, dp = extract_ports_from_info("54122 -> 80 [SYN]")
    assert (sp, dp) == (54122, 80)
    # Unicode arrow
    sp, dp = extract_ports_from_info("443 → 58900 [ACK]")
    assert (sp, dp) == (443, 58900)
    # Greater than
    sp, dp = extract_ports_from_info("53120 > 53 Len=30")
    assert (sp, dp) == (53120, 53)
    # Text format
    sp, dp = extract_ports_from_info("Query (src port: 53120, dst port: 53)")
    assert (sp, dp) == (53120, 53)
    # Invalid / no ports
    sp, dp = extract_ports_from_info("Who has 192.168.1.1? Tell 192.168.1.2")
    assert sp is None and dp is None


def test_pcap_parsing(analyzer, sample_pcap_path):
    records = analyzer.parse_file(sample_pcap_path)
    assert len(records) > 0
    stats = analyzer.calculate_statistics(records)
    assert stats["total_packets"] == len(records)
    assert stats["total_bytes"] > 0
    assert stats["ports_available"] is True


def test_flask_api_workflow():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. System status endpoint
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "tshark" in data

    # 2. Load sample data
    res = client.post("/api/load-sample", json={"format": "csv"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["is_sample"] is True
    assert data["stats"]["total_packets"] == 25

    # 3. Get statistics
    res = client.get("/api/statistics")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["stats"]["total_packets"] == 25

    # 4. Get paginated packets
    res = client.get("/api/packets?page=1&page_size=10")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["packets"]) == 10
    assert data["total_packets"] == 25
    assert data["total_pages"] == 3

    # 5. Filter packets by protocol
    res = client.get("/api/packets?protocol=DNS")
    assert res.status_code == 200
    data = res.get_json()
    assert all(p["protocol"] == "DNS" for p in data["packets"])

    # 6. Get single packet detail
    res = client.get("/api/packet/1")
    assert res.status_code == 200
    data = res.get_json()
    assert data["packet"]["no"] == 1

    # 7. Test export endpoints
    for exp_type in ["csv", "summary-json", "summary-csv"]:
        res = client.get(f"/api/export/{exp_type}")
        assert res.status_code == 200
        assert len(res.data) > 0

    # 8. Clear analysis
    res = client.post("/api/clear")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
