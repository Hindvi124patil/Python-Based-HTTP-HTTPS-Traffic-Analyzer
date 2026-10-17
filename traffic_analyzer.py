"""
NetScope — HTTP/HTTPS Traffic Analyzer
Core Engine: Packet dissection, CSV parsing, TShark integration, Scapy fallback, and statistical analysis.
"""

import os
import re
import csv
import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd


# ---------------------------------------------------------
# Well-Known Port Registry & Service Mapping
# ---------------------------------------------------------
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-Data (File Transfer)",
    21: "FTP-Control (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name System)",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP (Trivial FTP)",
    80: "HTTP (World Wide Web)",
    110: "POP3 (Post Office Protocol)",
    123: "NTP (Network Time)",
    143: "IMAP (Internet Message Access)",
    161: "SNMP (Network Management)",
    194: "IRC (Internet Relay Chat)",
    443: "HTTPS / TLS / QUIC",
    445: "SMB (Microsoft File Sharing)",
    465: "SMTPS (Secure SMTP)",
    587: "SMTP Submission",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL Server",
    1521: "Oracle DB",
    3306: "MySQL DB",
    3389: "RDP (Remote Desktop)",
    5353: "mDNS (Multicast DNS)",
    5432: "PostgreSQL DB",
    8000: "HTTP-Alt / Dev Server",
    8080: "HTTP-Proxy / Alt",
    8443: "HTTPS-Alt / Dev SSL",
    8888: "HTTP-Alt"
}


# ---------------------------------------------------------
# Unified Packet Record
# ---------------------------------------------------------
@dataclass
class PacketRecord:
    no: int
    timestamp: Optional[float]
    time_str: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    tcp_flags: Optional[str]
    info: str
    tls_sni: Optional[str]
    traffic_category: str
    identification_type: str
    is_encrypted: bool
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------
# TShark Detection Utility
# ---------------------------------------------------------
class TSharkDetector:
    """Locates and validates TShark executable on the host system."""

    @staticmethod
    def get_tshark_path() -> Optional[str]:
        # 1. Environment override
        env_path = os.environ.get("WIRESHARK_PATH") or os.environ.get("TSHARK_PATH")
        if env_path and os.path.isfile(env_path):
            return env_path

        # 2. PATH resolution
        which_path = shutil.which("tshark")
        if which_path:
            return which_path

        # 3. Standard Windows installation paths
        win_candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
            os.path.expandvars(r"%PROGRAMFILES%\Wireshark\tshark.exe")
        ]
        for candidate in win_candidates:
            if os.path.isfile(candidate):
                return candidate

        return None

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        path = cls.get_tshark_path()
        if not path:
            return {
                "available": False,
                "path": None,
                "version": None,
                "message": (
                    "TShark is not found in standard system paths. NetScope will use "
                    "native Scapy engine for PCAP files and pandas for CSV files. "
                    "To enable native Wireshark dissection, install Wireshark and add it to PATH."
                )
            }
        try:
            res = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=5)
            first_line = res.stdout.splitlines()[0] if res.stdout else "TShark"
            return {
                "available": True,
                "path": path,
                "version": first_line,
                "message": f"TShark detected and ready ({first_line})."
            }
        except Exception as e:
            return {
                "available": False,
                "path": path,
                "version": None,
                "message": f"TShark found at {path} but failed execution: {str(e)}"
            }


# ---------------------------------------------------------
# Port Extraction & Traffic Classification Helpers
# ---------------------------------------------------------
def clean_column_name(col: str) -> str:
    """Normalize column header: lowercase, stripped, without quotes/dots/underscores."""
    c = str(col).strip().lower()
    c = re.sub(r'[\s\.\-_"\'\(\)]+', '', c)
    return c


def extract_ports_from_info(info_text: str, protocol: str = "") -> Tuple[Optional[int], Optional[int]]:
    """
    Extracts source and destination ports reliably from Info column text.
    Handles Wireshark arrow formats: '54122 -> 80', '54122 → 80', '54122 > 80',
    or text format: '(src port: 53120, dst port: 53)', '(54122 -> 80)'.
    """
    if not info_text:
        return None, None

    # Check arrow patterns: 12345 -> 80, 12345 → 80, 12345 > 80
    arrow_pattern = re.search(r'\b(\d{1,5})\s*(?:->|→|>)\s*(\d{1,5})\b', info_text)
    if arrow_pattern:
        sp, dp = int(arrow_pattern.group(1)), int(arrow_pattern.group(2))
        if 1 <= sp <= 65535 and 1 <= dp <= 65535:
            return sp, dp

    # Check text patterns: src port: 53120, dst port: 53
    src_match = re.search(r'(?:src(?:_|\s*)port|sport|source(?:\s*)port)[:=\s]+(\d{1,5})\b', info_text, re.IGNORECASE)
    dst_match = re.search(r'(?:dst(?:_|\s*)port|dport|destination(?:\s*)port)[:=\s]+(\d{1,5})\b', info_text, re.IGNORECASE)
    if src_match and dst_match:
        sp, dp = int(src_match.group(1)), int(dst_match.group(1))
        if 1 <= sp <= 65535 and 1 <= dp <= 65535:
            return sp, dp

    # Check parentheses pattern: (54122 -> 80)
    paren_pattern = re.search(r'\(\s*(\d{1,5})\s*(?:->|→|>)\s*(\d{1,5})\s*\)', info_text)
    if paren_pattern:
        sp, dp = int(paren_pattern.group(1)), int(paren_pattern.group(2))
        if 1 <= sp <= 65535 and 1 <= dp <= 65535:
            return sp, dp

    return None, None


def extract_sni_from_info(info_text: str) -> Optional[str]:
    """Extracts TLS Server Name Indication (SNI) if present in info string."""
    if not info_text:
        return None
    sni_match = re.search(r'\[\s*(?:SNI|server_name)[:=\s]+([a-zA-Z0-9\.\-_]+)\s*\]', info_text, re.IGNORECASE)
    if sni_match:
        return sni_match.group(1)
    sni_alt = re.search(r'server_name=([a-zA-Z0-9\.\-_]+)', info_text, re.IGNORECASE)
    if sni_alt:
        return sni_alt.group(1)
    return None


def decode_tcp_flags(flags_val: Any) -> Optional[str]:
    """Decodes hex flags (0x0002, 0x012) or string flags into human-readable list."""
    if flags_val is None or pd.isna(flags_val):
        return None
    s = str(flags_val).strip()
    if not s or s.lower() == 'nan':
        return None

    if s.startswith("[") and s.endswith("]"):
        return s

    # Parse hex representation like 0x0002 or 0x012
    if s.startswith("0x") or s.startswith("0X"):
        try:
            val = int(s, 16)
            active = []
            if val & 0x001: active.append("FIN")
            if val & 0x002: active.append("SYN")
            if val & 0x004: active.append("RST")
            if val & 0x008: active.append("PSH")
            if val & 0x010: active.append("ACK")
            if val & 0x020: active.append("URG")
            if val & 0x040: active.append("ECE")
            if val & 0x080: active.append("CWR")
            return f"[{', '.join(active)}]" if active else s
        except ValueError:
            return s

    return s


def classify_traffic(
    protocol: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    info: str,
    tls_sni: Optional[str]
) -> Tuple[str, str, bool, str]:
    """
    Classifies a packet into traffic category, identification method, encryption status, and educational notes.
    Distinguishes confirmed protocol dissection from port-based inference.
    """
    proto_upper = (protocol or "").upper().strip()
    info_upper = (info or "").upper()
    has_port = lambda p: (src_port == p or dst_port == p)

    # 1. HTTP Traffic
    if proto_upper in ["HTTP", "HTTP/1.1", "HTTP/2", "HTTP2"] or "HTTP/1." in info_upper or "GET /" in info_upper or "POST /" in info_upper:
        return (
            "HTTP",
            "Protocol Dissected (Verified)",
            False,
            "Cleartext HTTP application layer traffic. Request/response headers and body are fully visible."
        )
    if proto_upper == "TCP" and (has_port(80) or has_port(8080)):
        return (
            "HTTP",
            "Port-Based Inference (Port 80/8080)",
            False,
            "TCP transport packet on standard HTTP port 80/8080. Inferred as HTTP traffic."
        )

    # 2. HTTPS / TLS Traffic
    tls_protos = ["TLS", "TLSV1", "TLSV1.0", "TLSV1.1", "TLSV1.2", "TLSV1.3", "SSL", "SSLV3"]
    is_tls_dissected = (
        proto_upper in tls_protos or
        any(k in info_upper for k in ["CLIENT HELLO", "SERVER HELLO", "CHANGE CIPHER SPEC", "APPLICATION DATA", "ENCRYPTED ALERT"]) or
        bool(tls_sni)
    )
    if is_tls_dissected:
        is_app_data = "APPLICATION DATA" in info_upper or "ENCRYPTED" in info_upper
        notes = (
            "Encrypted TLS payload (AES-GCM / ChaCha20). Payload contents cannot be read without session keys."
            if is_app_data else
            f"TLS Handshake message. Server Name Indication (SNI): {tls_sni or 'N/A'}."
        )
        return (
            "HTTPS/TLS",
            "Protocol Dissected (Verified)",
            True,
            notes
        )
    if proto_upper == "TCP" and (has_port(443) or has_port(8443)):
        return (
            "HTTPS/TLS",
            "Port-Based Inference (Port 443)",
            False,
            "TCP transport control packet (e.g., SYN, ACK, FIN) on HTTPS port 443. Port-inferred web traffic."
        )

    # 3. QUIC / HTTP/3 Traffic
    if proto_upper in ["QUIC", "GQUIC", "HTTP3", "HTTP/3"] or "INITIAL, DCID=" in info_upper or "1-RTT" in info_upper:
        return (
            "QUIC",
            "Protocol Dissected (Verified)",
            True,
            "QUIC (HTTP/3) transport layer over UDP. Multiplexed, built-in TLS 1.3 encrypted payload."
        )
    if proto_upper == "UDP" and has_port(443):
        return (
            "QUIC",
            "Port-Based Inference (UDP 443)",
            True,
            "UDP packet on port 443, typical for QUIC / HTTP/3 traffic."
        )

    # 4. DNS Traffic
    if proto_upper in ["DNS", "MDNS", "LLMNR"] or has_port(53) or has_port(5353):
        id_type = "Protocol Dissected (Verified)" if proto_upper in ["DNS", "MDNS", "LLMNR"] else "Port-Based Inference (Port 53)"
        return (
            "DNS",
            id_type,
            False,
            "Domain Name System resolution packet (domain lookup query or IP response)."
        )

    # 5. Generic TCP / UDP
    if proto_upper == "TCP":
        return (
            "TCP",
            "Transport Layer Dissected",
            False,
            "Standard Transmission Control Protocol packet."
        )
    if proto_upper == "UDP":
        return (
            "UDP",
            "Transport Layer Dissected",
            False,
            "Standard User Datagram Protocol packet."
        )

    # 6. Other protocols (ARP, ICMP, etc.)
    return (
        proto_upper if proto_upper else "Other",
        "Dissected Protocol",
        False,
        f"Network traffic protocol: {proto_upper or 'Unknown'}."
    )


# ---------------------------------------------------------
# Core Traffic Analyzer
# ---------------------------------------------------------
class TrafficAnalyzer:
    """Parses capture files (CSV, PCAP, PCAPNG) and computes statistical metrics."""

    def __init__(self):
        self.tshark_info = TSharkDetector.get_status()

    def parse_file(self, filepath: str) -> List[PacketRecord]:
        """Dispatches to CSV or PCAP parser based on extension."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".csv":
            return self.parse_csv(filepath)
        elif ext in [".pcap", ".pcapng", ".cap"]:
            return self.parse_pcap(filepath)
        else:
            raise ValueError(f"Unsupported file format '{ext}'. NetScope accepts .csv, .pcap, and .pcapng files.")

    def parse_csv(self, filepath: str) -> List[PacketRecord]:
        """Parses a Wireshark-exported CSV file with header normalization."""
        try:
            df = pd.read_csv(filepath, encoding="utf-8-sig", on_bad_lines="skip")
        except Exception:
            try:
                df = pd.read_csv(filepath, encoding="latin1", on_bad_lines="skip")
            except Exception as e:
                raise ValueError(f"Failed to read CSV file: {str(e)}")

        if df.empty:
            return []

        # Map column names
        col_map: Dict[str, str] = {}
        for original_col in df.columns:
            cleaned = clean_column_name(original_col)
            # Packet number
            if cleaned in ["no", "no.", "packet", "packetno", "number", "id", "framenumber"]:
                col_map["no"] = original_col
            # Timestamp
            elif cleaned in ["time", "timestamp", "frametimeepoch", "timeepoch", "relativetime", "frametimerelative"]:
                col_map["time"] = original_col
            # Source IP
            elif cleaned in ["source", "src", "sourceip", "ipsrc", "srcip", "sourceaddress"]:
                col_map["source"] = original_col
            # Destination IP
            elif cleaned in ["destination", "dest", "dst", "destinationip", "ipdst", "dstip", "destinationaddress"]:
                col_map["destination"] = original_col
            # Protocol
            elif cleaned in ["protocol", "proto", "wscolprotocol"]:
                col_map["protocol"] = original_col
            # Length
            elif cleaned in ["length", "len", "packetlength", "framelen", "bytes"]:
                col_map["length"] = original_col
            # Info
            elif cleaned in ["info", "information", "summary", "wscolinfo", "packetinfo"]:
                col_map["info"] = original_col
            # Ports if present
            elif cleaned in ["sourceport", "srcport", "sport", "tcpsrcport", "udpsrcport"]:
                col_map["src_port"] = original_col
            elif cleaned in ["destinationport", "destport", "dstport", "dport", "tcpdstport", "udpdstport"]:
                col_map["dst_port"] = original_col
            # TCP flags
            elif cleaned in ["flags", "tcpflags"]:
                col_map["flags"] = original_col
            # TLS SNI
            elif cleaned in ["tlshandshakeextensionsservername", "sni", "servername"]:
                col_map["sni"] = original_col

        records: List[PacketRecord] = []
        for idx, row in df.iterrows():
            # Packet No
            raw_no = row.get(col_map.get("no")) if "no" in col_map else (idx + 1)
            try:
                packet_no = int(float(raw_no))
            except (ValueError, TypeError):
                packet_no = idx + 1

            # Timestamp
            raw_time = row.get(col_map.get("time")) if "time" in col_map else None
            timestamp_val: Optional[float] = None
            time_display = "N/A"
            if raw_time is not None and not pd.isna(raw_time):
                time_str_raw = str(raw_time).strip()
                try:
                    timestamp_val = float(time_str_raw)
                    time_display = f"{timestamp_val:.6f}s"
                except ValueError:
                    time_display = time_str_raw

            # Source & Destination
            src_ip = str(row.get(col_map.get("source"), "N/A")).strip()
            dst_ip = str(row.get(col_map.get("destination"), "N/A")).strip()
            if src_ip == "nan" or not src_ip: src_ip = "N/A"
            if dst_ip == "nan" or not dst_ip: dst_ip = "N/A"

            # Protocol
            protocol = str(row.get(col_map.get("protocol"), "TCP")).strip()
            if protocol == "nan" or not protocol: protocol = "TCP"

            # Length
            raw_len = row.get(col_map.get("length")) if "length" in col_map else 0
            try:
                pkt_len = int(float(raw_len))
            except (ValueError, TypeError):
                pkt_len = 0

            # Info
            info_text = str(row.get(col_map.get("info"), "")).strip()
            if info_text == "nan": info_text = ""

            # Ports: check columns first, else try to extract from Info
            src_port: Optional[int] = None
            dst_port: Optional[int] = None

            if "src_port" in col_map and not pd.isna(row.get(col_map["src_port"])):
                try:
                    src_port = int(float(row[col_map["src_port"]]))
                except (ValueError, TypeError):
                    pass
            if "dst_port" in col_map and not pd.isna(row.get(col_map["dst_port"])):
                try:
                    dst_port = int(float(row[col_map["dst_port"]]))
                except (ValueError, TypeError):
                    pass

            # If ports are missing from dedicated columns, attempt regex extraction from Info
            if src_port is None and dst_port is None and info_text:
                ext_sp, ext_dp = extract_ports_from_info(info_text, protocol)
                if ext_sp is not None: src_port = ext_sp
                if ext_dp is not None: dst_port = ext_dp

            # TCP Flags
            raw_flags = row.get(col_map.get("flags")) if "flags" in col_map else None
            tcp_flags = decode_tcp_flags(raw_flags)
            if not tcp_flags and info_text:
                # check if flags are in info: [SYN], [ACK], etc.
                flags_match = re.search(r'\[(SYN|ACK|FIN|RST|PSH|URG|SYN,\s*ACK|FIN,\s*ACK|PSH,\s*ACK)\]', info_text)
                if flags_match:
                    tcp_flags = f"[{flags_match.group(1)}]"

            # TLS SNI
            tls_sni: Optional[str] = None
            if "sni" in col_map and not pd.isna(row.get(col_map["sni"])):
                s = str(row[col_map["sni"]]).strip()
                if s and s != "nan": tls_sni = s
            if not tls_sni and info_text:
                tls_sni = extract_sni_from_info(info_text)

            # Classify traffic
            cat, id_type, encrypted, notes = classify_traffic(protocol, src_port, dst_port, info_text, tls_sni)

            records.append(PacketRecord(
                no=packet_no,
                timestamp=timestamp_val,
                time_str=time_display,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=pkt_len,
                tcp_flags=tcp_flags,
                info=info_text,
                tls_sni=tls_sni,
                traffic_category=cat,
                identification_type=id_type,
                is_encrypted=encrypted,
                notes=notes
            ))

        return records

    def parse_pcap(self, filepath: str) -> List[PacketRecord]:
        """Parses PCAP / PCAPNG using TShark if available, otherwise Scapy."""
        tshark_path = TSharkDetector.get_tshark_path()
        if tshark_path:
            try:
                return self._parse_pcap_tshark(filepath, tshark_path)
            except Exception as e:
                # Fallback to Scapy if TShark fails
                return self._parse_pcap_scapy(filepath)
        else:
            return self._parse_pcap_scapy(filepath)

    def _parse_pcap_tshark(self, filepath: str, tshark_path: str) -> List[PacketRecord]:
        """Executes TShark CLI to extract dissected fields into CSV format."""
        cmd = [
            tshark_path,
            "-r", filepath,
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=|",
            "-E", "quote=d",
            "-E", "occurrence=f",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.flags",
            "-e", "_ws.col.Info",
            "-e", "tls.handshake.extensions_server_name"
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if not res.stdout.strip():
            return []

        # Read the CSV output directly via StringIO
        import io
        df = pd.read_csv(io.StringIO(res.stdout), sep="|", on_bad_lines="skip")
        if df.empty:
            return []

        records: List[PacketRecord] = []
        for idx, row in df.iterrows():
            packet_no = int(row.get("frame.number", idx + 1)) if not pd.isna(row.get("frame.number")) else (idx + 1)
            raw_time = row.get("frame.time_epoch")
            timestamp_val: Optional[float] = None
            time_display = "N/A"
            if not pd.isna(raw_time):
                try:
                    timestamp_val = float(raw_time)
                    time_display = f"{timestamp_val:.6f}s"
                except (ValueError, TypeError):
                    time_display = str(raw_time)

            
            
            # IP Source / Destination
            def get_valid_value(row, *columns):
                for column in columns:
                    value = row.get(column)
                    if value is None or pd.isna(value):
                        continue

                    value = str(value).strip().strip('"')
                    if value and value.lower() != "nan":
                        return value

                return "N/A"

            src_ip = get_valid_value(row, "ip.src", "ipv6.src")
            dst_ip = get_valid_value(row, "ip.dst", "ipv6.dst")


            # Ports
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            sp_raw = row.get("tcp.srcport") if not pd.isna(row.get("tcp.srcport")) else row.get("udp.srcport")
            dp_raw = row.get("tcp.dstport") if not pd.isna(row.get("tcp.dstport")) else row.get("udp.dstport")
            if not pd.isna(sp_raw):
                try: src_port = int(float(str(sp_raw).split(",")[0]))
                except (ValueError, TypeError): pass
            if not pd.isna(dp_raw):
                try: dst_port = int(float(str(dp_raw).split(",")[0]))
                except (ValueError, TypeError): pass

           
            # Protocol
            proto_value = row.get("_ws.col.protocol", row.get("_ws.col.Protocol", "TCP"))
            proto = str(proto_value).strip()

            if not proto or proto.lower() == "nan":
               proto = "TCP"

            # Length
            length = int(float(row.get("frame.len", 0))) if not pd.isna(row.get("frame.len")) else 0

            # TCP flags
            raw_flags = row.get("tcp.flags")
            tcp_flags = decode_tcp_flags(raw_flags)

            # Info
            info_text = str(row.get("_ws.col.Info", "")).strip()
            if info_text == "nan": info_text = ""

            # TLS SNI
            tls_sni = None
            raw_sni = row.get("tls.handshake.extensions_server_name")
            if not pd.isna(raw_sni) and str(raw_sni).strip():
                tls_sni = str(raw_sni).strip()

            cat, id_type, encrypted, notes = classify_traffic(proto, src_port, dst_port, info_text, tls_sni)

            records.append(PacketRecord(
                no=packet_no,
                timestamp=timestamp_val,
                time_str=time_display,
                src_ip=str(src_ip),
                dst_ip=str(dst_ip),
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                length=length,
                tcp_flags=tcp_flags,
                info=info_text,
                tls_sni=tls_sni,
                traffic_category=cat,
                identification_type=id_type,
                is_encrypted=encrypted,
                notes=notes
            ))

        return records

    def _parse_pcap_scapy(self, filepath: str) -> List[PacketRecord]:
        """Fallback Scapy parser for PCAP / PCAPNG files."""
        try:
            from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, ARP, ICMP
        except ImportError:
            raise ImportError("Scapy is required as fallback parser but is not installed.")

        try:
            packets = rdpcap(filepath)
        except Exception as e:
            raise ValueError(f"Scapy failed to parse capture file: {str(e)}")

        records: List[PacketRecord] = []
        for idx, pkt in enumerate(packets):
            packet_no = idx + 1
            timestamp_val = float(pkt.time) if hasattr(pkt, "time") else None
            time_display = f"{timestamp_val:.6f}s" if timestamp_val is not None else "N/A"
            length = len(pkt)

            src_ip = "N/A"
            dst_ip = "N/A"
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            elif pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst

            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            tcp_flags: Optional[str] = None
            proto = "Other"

            if pkt.haslayer(TCP):
                proto = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                flag_str = str(pkt[TCP].flags)
                tcp_flags = f"[{flag_str}]"
            elif pkt.haslayer(UDP):
                proto = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
            elif pkt.haslayer(ARP):
                proto = "ARP"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            # Check application protocols
            if pkt.haslayer(DNS):
                proto = "DNS"
            elif src_port == 80 or dst_port == 80:
                proto = "HTTP"
            elif src_port == 443 or dst_port == 443:
                proto = "TLSv1.3" if pkt.haslayer(TCP) else "QUIC"

            info_text = f"{src_ip}:{src_port or 'N/A'} -> {dst_ip}:{dst_port or 'N/A'} [{proto}] Len={length}"
            tls_sni = None
            cat, id_type, encrypted, notes = classify_traffic(proto, src_port, dst_port, info_text, tls_sni)

            records.append(PacketRecord(
                no=packet_no,
                timestamp=timestamp_val,
                time_str=time_display,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                length=length,
                tcp_flags=tcp_flags,
                info=info_text,
                tls_sni=tls_sni,
                traffic_category=cat,
                identification_type=id_type,
                is_encrypted=encrypted,
                notes=notes
            ))

        return records

    def calculate_statistics(self, records: List[PacketRecord]) -> Dict[str, Any]:
        """Calculates all network metrics, aggregations, and visual chart data."""
        if not records:
            return {
                "is_empty": True,
                "total_packets": 0,
                "total_bytes": 0,
                "min_packet_size": 0,
                "max_packet_size": 0,
                "mean_packet_size": 0.0,
                "median_packet_size": 0.0,
                "protocol_counts": {},
                "protocol_percentages": {},
                "protocol_bytes": {},
                "category_counts": {},
                "category_percentages": {},
                "category_bytes": {},
                "verification_breakdown": {
                    "http_confirmed": 0, "http_inferred": 0,
                    "https_confirmed": 0, "https_inferred": 0,
                    "quic_confirmed": 0, "quic_inferred": 0
                },
                "top_source_ips": [],
                "top_destination_ips": [],
                "top_ip_pairs": [],
                "ports_available": False,
                "top_source_ports": [],
                "top_destination_ports": [],
                "timestamps_available": False,
                "start_time": None,
                "end_time": None,
                "duration_seconds": 0.0,
                "duration_formatted": "0.00s",
                "traffic_over_time": {"labels": [], "packet_counts": [], "byte_counts": []},
                "size_distribution": {"labels": [], "counts": [], "percentages": []},
                "web_traffic_summary": {
                    "total_web_packets": 0,
                    "http_count": 0,
                    "https_count": 0,
                    "quic_count": 0,
                    "dns_count": 0,
                    "tls_domains": [],
                    "http_methods": {},
                    "encryption_note": "No packets found in capture."
                },
                "unavailable_fields": ["All fields (empty capture)"]
            }

        total_packets = len(records)
        lengths = [p.length for p in records]
        total_bytes = sum(lengths)

        # NumPy calculations for packet sizes
        min_size = int(np.min(lengths))
        max_size = int(np.max(lengths))
        mean_size = round(float(np.mean(lengths)), 2)
        median_size = round(float(np.median(lengths)), 2)

        # Protocols distribution
        proto_series = pd.Series([p.protocol for p in records])
        proto_counts_dict = proto_series.value_counts().to_dict()
        proto_percentages = {k: round((v / total_packets) * 100, 2) for k, v in proto_counts_dict.items()}

        proto_bytes_dict: Dict[str, int] = {}
        for p in records:
            proto_bytes_dict[p.protocol] = proto_bytes_dict.get(p.protocol, 0) + p.length

        # Categories distribution
        cat_series = pd.Series([p.traffic_category for p in records])
        cat_counts_dict = cat_series.value_counts().to_dict()
        cat_percentages = {k: round((v / total_packets) * 100, 2) for k, v in cat_counts_dict.items()}

        cat_bytes_dict: Dict[str, int] = {}
        for p in records:
            cat_bytes_dict[p.traffic_category] = cat_bytes_dict.get(p.traffic_category, 0) + p.length

        # Verification breakdown
        verification = {
            "http_confirmed": sum(1 for p in records if p.traffic_category == "HTTP" and "Verified" in p.identification_type),
            "http_inferred": sum(1 for p in records if p.traffic_category == "HTTP" and "Inference" in p.identification_type),
            "https_confirmed": sum(1 for p in records if p.traffic_category == "HTTPS/TLS" and "Verified" in p.identification_type),
            "https_inferred": sum(1 for p in records if p.traffic_category == "HTTPS/TLS" and "Inference" in p.identification_type),
            "quic_confirmed": sum(1 for p in records if p.traffic_category == "QUIC" and "Verified" in p.identification_type),
            "quic_inferred": sum(1 for p in records if p.traffic_category == "QUIC" and "Inference" in p.identification_type),
        }

        # Top Source and Destination IPs
        src_ips = [p.src_ip for p in records if p.src_ip != "N/A"]
        dst_ips = [p.dst_ip for p in records if p.dst_ip != "N/A"]

        top_src_ips = []
        if src_ips:
            src_counts = pd.Series(src_ips).value_counts().head(10)
            src_bytes = {}
            for p in records:
                if p.src_ip in src_counts:
                    src_bytes[p.src_ip] = src_bytes.get(p.src_ip, 0) + p.length
            for ip, cnt in src_counts.items():
                top_src_ips.append({
                    "ip": ip,
                    "count": int(cnt),
                    "bytes": src_bytes.get(ip, 0),
                    "percentage": round((cnt / total_packets) * 100, 2)
                })

        top_dst_ips = []
        if dst_ips:
            dst_counts = pd.Series(dst_ips).value_counts().head(10)
            dst_bytes = {}
            for p in records:
                if p.dst_ip in dst_counts:
                    dst_bytes[p.dst_ip] = dst_bytes.get(p.dst_ip, 0) + p.length
            for ip, cnt in dst_counts.items():
                top_dst_ips.append({
                    "ip": ip,
                    "count": int(cnt),
                    "bytes": dst_bytes.get(ip, 0),
                    "percentage": round((cnt / total_packets) * 100, 2)
                })

        # Top IP Conversations (Pairs)
        pairs = {}
        for p in records:
            if p.src_ip != "N/A" and p.dst_ip != "N/A":
                pair_key = " <-> ".join(sorted([p.src_ip, p.dst_ip]))
                if pair_key not in pairs:
                    pairs[pair_key] = {"count": 0, "bytes": 0}
                pairs[pair_key]["count"] += 1
                pairs[pair_key]["bytes"] += p.length

        top_ip_pairs = sorted(
            [{"pair": k, "count": v["count"], "bytes": v["bytes"]} for k, v in pairs.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:10]

        # Port Analysis
        src_ports = [p.src_port for p in records if p.src_port is not None]
        dst_ports = [p.dst_port for p in records if p.dst_port is not None]
        ports_available = len(src_ports) > 0 or len(dst_ports) > 0

        top_src_ports = []
        top_dst_ports = []
        if src_ports:
            sp_series = pd.Series(src_ports).value_counts().head(10)
            for port, cnt in sp_series.items():
                top_src_ports.append({
                    "port": int(port),
                    "service": WELL_KNOWN_PORTS.get(int(port), "Dynamic / Private Port"),
                    "count": int(cnt),
                    "percentage": round((cnt / len(src_ports)) * 100, 2)
                })

        if dst_ports:
            dp_series = pd.Series(dst_ports).value_counts().head(10)
            for port, cnt in dp_series.items():
                top_dst_ports.append({
                    "port": int(port),
                    "service": WELL_KNOWN_PORTS.get(int(port), "Dynamic / Private Port"),
                    "count": int(cnt),
                    "percentage": round((cnt / len(dst_ports)) * 100, 2)
                })

        # Timestamp and Duration
        valid_timestamps = [p.timestamp for p in records if p.timestamp is not None]
        timestamps_available = len(valid_timestamps) >= 2
        start_ts = min(valid_timestamps) if valid_timestamps else None
        end_ts = max(valid_timestamps) if valid_timestamps else None
        duration = (end_ts - start_ts) if (start_ts is not None and end_ts is not None) else 0.0

        if duration < 60:
            duration_formatted = f"{duration:.2f}s"
        else:
            mins = int(duration // 60)
            secs = duration % 60
            duration_formatted = f"{mins}m {secs:.1f}s"

        # Traffic Over Time (Binning)
        traffic_over_time = {"labels": [], "packet_counts": [], "byte_counts": []}
        if timestamps_available and duration > 0:
            num_bins = min(20, max(5, int(duration) + 1))
            bin_edges = np.linspace(start_ts, end_ts, num_bins + 1)
            binned_counts = [0] * num_bins
            binned_bytes = [0] * num_bins

            for p in records:
                if p.timestamp is not None:
                    # find bin
                    idx = np.searchsorted(bin_edges, p.timestamp) - 1
                    idx = max(0, min(num_bins - 1, idx))
                    binned_counts[idx] += 1
                    binned_bytes[idx] += p.length

            labels = [f"+{(edge - start_ts):.1f}s" for edge in bin_edges[:-1]]
            traffic_over_time = {
                "labels": labels,
                "packet_counts": binned_counts,
                "byte_counts": binned_bytes
            }
        else:
            # Fallback: slice by index chunks
            chunk_size = max(1, total_packets // 10)
            labels = [f"Pkt {i*chunk_size+1}-{(i+1)*chunk_size}" for i in range(10 if total_packets >= 10 else 1)]
            counts = []
            b_counts = []
            for i in range(len(labels)):
                subset = records[i*chunk_size:(i+1)*chunk_size]
                counts.append(len(subset))
                b_counts.append(sum(p.length for p in subset))
            traffic_over_time = {
                "labels": labels,
                "packet_counts": counts,
                "byte_counts": b_counts
            }

        # Packet Size Distribution (Histogram bins)
        size_bins = [
            ("< 128 B", lambda l: l < 128),
            ("128 - 511 B", lambda l: 128 <= l < 512),
            ("512 - 1023 B", lambda l: 512 <= l < 1024),
            ("1024 - 1514 B", lambda l: 1024 <= l <= 1514),
            ("> 1514 B (Jumbo)", lambda l: l > 1514)
        ]
        size_dist_labels = []
        size_dist_counts = []
        size_dist_percentages = []
        for label, cond in size_bins:
            cnt = sum(1 for l in lengths if cond(l))
            size_dist_labels.append(label)
            size_dist_counts.append(cnt)
            size_dist_percentages.append(round((cnt / total_packets) * 100, 2))

        # Web Traffic Deep Dive
        tls_domains = sorted(list({p.tls_sni for p in records if p.tls_sni}))
        http_methods: Dict[str, int] = {}
        for p in records:
            if p.traffic_category == "HTTP":
                for m in ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]:
                    if f"{m} " in p.info.upper():
                        http_methods[m] = http_methods.get(m, 0) + 1

        web_total = (
            cat_counts_dict.get("HTTP", 0) +
            cat_counts_dict.get("HTTPS/TLS", 0) +
            cat_counts_dict.get("QUIC", 0)
        )

        encryption_notice = (
            "Security Notice: HTTPS and QUIC application payloads are encrypted using symmetric ciphers "
            "(e.g., AES-GCM, ChaCha20-Poly1305) negotiated via TLS handshake. In NetScope, protocol metadata, "
            "Server Name Indication (SNI), packet timing, and size can be inspected, but payload contents "
            "remain cryptographically protected without authorized TLS pre-master secret key logs."
        )

        # Unavailable fields detection
        unavailable = []
        if not ports_available:
            unavailable.append("Communication Ports (Source/Destination Ports not in CSV)")
        if not timestamps_available:
            unavailable.append("Absolute Timestamps (Duration cannot be computed)")
        if not any(p.tcp_flags for p in records):
            unavailable.append("TCP Flags (Flags not exported in CSV)")
        if not any(p.tls_sni for p in records):
            unavailable.append("TLS Server Name Indication (SNI)")

        return {
            "is_empty": False,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "min_packet_size": min_size,
            "max_packet_size": max_size,
            "mean_packet_size": mean_size,
            "median_packet_size": median_size,
            "protocol_counts": proto_counts_dict,
            "protocol_percentages": proto_percentages,
            "protocol_bytes": proto_bytes_dict,
            "category_counts": cat_counts_dict,
            "category_percentages": cat_percentages,
            "category_bytes": cat_bytes_dict,
            "verification_breakdown": verification,
            "top_source_ips": top_src_ips,
            "top_destination_ips": top_dst_ips,
            "top_ip_pairs": top_ip_pairs,
            "ports_available": ports_available,
            "top_source_ports": top_src_ports,
            "top_destination_ports": top_dst_ports,
            "timestamps_available": timestamps_available,
            "start_time": f"{start_ts:.6f}s" if start_ts is not None else None,
            "end_time": f"{end_ts:.6f}s" if end_ts is not None else None,
            "duration_seconds": round(duration, 3),
            "duration_formatted": duration_formatted,
            "traffic_over_time": traffic_over_time,
            "size_distribution": {
                "labels": size_dist_labels,
                "counts": size_dist_counts,
                "percentages": size_dist_percentages
            },
            "web_traffic_summary": {
                "total_web_packets": web_total,
                "http_count": cat_counts_dict.get("HTTP", 0),
                "https_count": cat_counts_dict.get("HTTPS/TLS", 0),
                "quic_count": cat_counts_dict.get("QUIC", 0),
                "dns_count": cat_counts_dict.get("DNS", 0),
                "tls_domains": tls_domains,
                "http_methods": http_methods,
                "encryption_note": encryption_notice
            },
            "unavailable_fields": unavailable
        }

    def export_analyzed_csv(self, records: List[PacketRecord], output_path: str) -> str:
        """Exports enriched analyzed packet data to CSV."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        fieldnames = [
            "no", "time_str", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "length", "tcp_flags", "traffic_category",
            "identification_type", "is_encrypted", "tls_sni", "info", "notes"
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in records:
                d = r.to_dict()
                # Clean up None values for display
                d["src_port"] = d["src_port"] if d["src_port"] is not None else "N/A"
                d["dst_port"] = d["dst_port"] if d["dst_port"] is not None else "N/A"
                d["tcp_flags"] = d["tcp_flags"] or "N/A"
                d["tls_sni"] = d["tls_sni"] or "N/A"
                writer.writerow(d)
        return output_path

    def export_statistics_json(self, stats: Dict[str, Any], output_path: str) -> str:
        """Exports statistical metrics dictionary as pretty JSON."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        return output_path

    def export_statistics_csv(self, stats: Dict[str, Any], output_path: str) -> str:
        """Exports key network statistics as a summary CSV table."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        summary_rows = [
            {"Metric": "Total Captured Packets", "Value": stats.get("total_packets", 0)},
            {"Metric": "Total Captured Bytes", "Value": stats.get("total_bytes", 0)},
            {"Metric": "Minimum Packet Size (Bytes)", "Value": stats.get("min_packet_size", 0)},
            {"Metric": "Maximum Packet Size (Bytes)", "Value": stats.get("max_packet_size", 0)},
            {"Metric": "Mean Packet Size (Bytes)", "Value": stats.get("mean_packet_size", 0.0)},
            {"Metric": "Median Packet Size (Bytes)", "Value": stats.get("median_packet_size", 0.0)},
            {"Metric": "Capture Duration", "Value": stats.get("duration_formatted", "N/A")},
            {"Metric": "Ports Available", "Value": "Yes" if stats.get("ports_available") else "No"},
            {"Metric": "Timestamps Available", "Value": "Yes" if stats.get("timestamps_available") else "No"},
            {"Metric": "HTTP Packets", "Value": stats.get("category_counts", {}).get("HTTP", 0)},
            {"Metric": "HTTPS/TLS Packets", "Value": stats.get("category_counts", {}).get("HTTPS/TLS", 0)},
            {"Metric": "QUIC Packets", "Value": stats.get("category_counts", {}).get("QUIC", 0)},
            {"Metric": "DNS Packets", "Value": stats.get("category_counts", {}).get("DNS", 0)}
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Metric", "Value"])
            writer.writeheader()
            writer.writerows(summary_rows)
        return output_path
