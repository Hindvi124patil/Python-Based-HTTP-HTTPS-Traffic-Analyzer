# NetScope — HTTP/HTTPS Traffic Analyzer
### Computer Networks Academic Project • Department of Computer Engineering

---

## 1. Project Title
**NetScope — Python-Based HTTP/HTTPS Traffic Analyzer**  
A full-stack, local network packet analysis dashboard designed for academic exploration of web traffic, transport layer communication, cryptography awareness, and statistical network telemetry.

---

## 2. Abstract
Modern internet communication heavily relies on the Hypertext Transfer Protocol (HTTP), Transport Layer Security (HTTPS / TLS 1.2 / TLS 1.3), and the new QUIC protocol (HTTP/3 over UDP). Understanding how client browsers establish connections, negotiate security parameters, and transfer payload data is fundamental to Computer Networks curricula. 

**NetScope** is a comprehensive, functional, and beginner-friendly network analysis system. Built with Python 3, Flask, pandas, and Chart.js, NetScope parses both raw binary packet captures (`.pcap`, `.pcapng`) and Wireshark-exported CSV traces. It extracts Layer 2 through Layer 7 metadata (IP addresses, communication ports, frame lengths, TCP flags, timestamps, and TLS Server Name Indications), distinguishes protocol-dissected packets from port-inferred packets, and visualizes network activity using interactive charts and sortable tables.

---

## 3. Problem Statement
In undergraduate Computer Networks laboratory courses, students frequently capture packets using GUI tools such as Wireshark. However, beginners often encounter significant learning hurdles:
1. Wireshark's vast feature set can be overwhelming for beginners seeking to isolate HTTP/HTTPS web flows.
2. Students often confuse transport-layer control packets (e.g., TCP SYN/ACK on port 443) with actual TLS-encrypted application records.
3. Students frequently assume that packet analyzers can decrypt HTTPS payloads without understanding the mathematical guarantees of symmetric and asymmetric cryptography.
4. Exporting data and calculating required statistical metrics (mean/median packet sizes, protocol distribution percentages, and bandwidth-over-time histograms) manually in spreadsheets is tedious and error-prone.

**NetScope** bridges this pedagogical gap by providing an automated, clear, and educational web interface that ingests capture files, performs statistical aggregations, verifies protocols, and presents network behavior cleanly.

---

## 4. Five Core Academic Objectives
This project satisfies all five mandatory syllabus objectives:

| Objective # | Objective Description | NetScope Implementation | Status |
| :--- | :--- | :--- | :---: |
| **Objective 1** | **Develop a Python program to analyze web traffic.** | Modular backend (`traffic_analyzer.py` and `app.py`) built in Python 3 with Flask REST endpoints. | **Satisfied** |
| **Objective 2** | **Capture HTTP/HTTPS-related packets using Wireshark.** | Full support for Wireshark `.pcap`, `.pcapng`, and exported `.csv` files via Wireshark's TShark CLI and Scapy fallback. | **Satisfied** |
| **Objective 3** | **Identify source & destination IP addresses and communication ports.** | Dissection and display of IPv4/IPv6 source/destination addresses, TCP/UDP communication ports, and IANA well-known service mapping. | **Satisfied** |
| **Objective 4** | **Analyze packet size, protocols, and packet transmission timestamps.** | NumPy-driven calculation of minimum, maximum, mean, and median packet lengths; time-bin interval tracking; protocol categorization. | **Satisfied** |
| **Objective 5** | **Calculate traffic statistics and display results using tables and graphs.** | Interactive Chart.js visualizations (doughnut, histograms, time series) and searchable, sortable, paginated tables. | **Satisfied** |

---

## 5. Software and Hardware Requirements

### Software Requirements
- **Operating System:** Windows 10 / Windows 11 (also runs on Linux and macOS)
- **Programming Language:** Python 3.9 or higher (Tested on Python 3.14)
- **Web Framework:** Flask 3.x
- **Data Analysis Libraries:** pandas, NumPy, Scapy
- **Packet Dissection Engine:** Wireshark & TShark (v4.x recommended, installed at standard path)
- **Frontend Technologies:** HTML5, CSS3, Modern JavaScript (ES6+)
- **Charting Engine:** Chart.js 4.4.x (bundled locally in `static/js/chart.umd.min.js` for 100% offline functionality)
- **Web Browser:** Google Chrome, Microsoft Edge, Mozilla Firefox, or Brave

### Hardware Requirements
- **Processor:** Intel Core i3 / AMD Ryzen 3 or higher
- **RAM:** 4 GB minimum (8 GB recommended for large capture files)
- **Storage:** 100 MB free disk space for project code and captures

---

## 6. System Architecture

```
+-------------------------------------------------------------------------------+
|                             DATA INPUT LAYER                                  |
|   1. Wireshark Binary Capture (.pcap / .pcapng)                               |
|   2. Wireshark Exported CSV (.csv)                                            |
|   3. Built-in Academic Sample Traces (sample_traffic.csv / .pcap)             |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                       INGESTION & DISSECTION ENGINE                           |
|                         (traffic_analyzer.py)                                 |
|                                                                               |
|   +--------------------------+          +---------------------------------+   |
|   |   TShark CLI Engine      |  --or--  |   Native Scapy / pandas Parser  |   |
|   | (Primary Dissector)      |          | (Fallback & CSV Processor)      |   |
|   +--------------------------+          +---------------------------------+   |
|                                                                               |
|   - Field Normalization: frame.number, ip.src, ip.dst, ports, protocol, len  |
|   - Port Extraction: Header columns or Regex parsing on Info column           |
|   - Traffic Classifier: HTTP vs HTTPS/TLS vs QUIC vs DNS vs TCP/UDP           |
|   - Cryptography Auditor: Distinguishes Verified Dissection vs Port Inference |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                         NUMERICAL & STATS ENGINE                              |
|                       (NumPy & pandas Aggregations)                           |
|                                                                               |
|   - Min, Max, Mean, Median Packet Sizes (Bytes)                               |
|   - Protocol Frequency & Byte Volume Percentages                              |
|   - Top Talkers (Source IPs) & Top Listeners (Destination IPs)                |
|   - IP Conversations (Bidirectional Node Pairs)                               |
|   - Time Bins (Traffic rate over session duration)                            |
|   - Ethernet MTU Bins (<128B, 128-511B, 512-1023B, 1024-1514B, >1514B)       |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                            FLASK REST API LAYER                               |
|                                  (app.py)                                     |
|                                                                               |
|   - GET  /                  -> Single Page Application (index.html)           |
|   - POST /api/upload        -> Multipart capture upload & instant parsing     |
|   - POST /api/load-sample   -> Loads pre-packaged academic demo traces        |
|   - GET  /api/statistics    -> Full telemetry metrics JSON                    |
|   - GET  /api/packets       -> Paginated, filtered, and sorted packet records |
|   - GET  /api/packet/<id>   -> Detailed single-frame inspector modal          |
|   - GET  /api/export/<type> -> Export analyzed CSV, stats CSV, or JSON        |
|   - GET  /api/status        -> Host environment & TShark health check         |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                           INTERACTIVE PRESENTATION                            |
|                   (Dark Navy SPA: HTML5 + CSS3 + Chart.js)                    |
|                                                                               |
|   - Overview KPI Cards & Mini Highlights                                      |
|   - Drag & Drop Upload Zone with Progress Feedback                            |
|   - Protocol Distribution Doughnut Chart                                      |
|   - Web Traffic Classification (HTTP vs HTTPS vs QUIC vs DNS)                 |
|   - Traffic Over Time Line Chart                                              |
|   - Packet Size Histogram Bar Chart                                           |
|   - Sortable, Searchable Packet Explorer Table with Inspector Drawer          |
|   - Print-Friendly Academic Summary Report (CSS @media print)                 |
+-------------------------------------------------------------------------------+
```

---

## 7. Working Methodology
1. **Packet Capture:** Traffic is generated by visiting web pages and recorded using Wireshark on the active network interface.
2. **File Ingestion:** The user uploads a `.pcap`, `.pcapng`, or `.csv` file via NetScope's drag-and-drop web dropzone.
3. **Dissection & Normalization:**
   - For `.pcap` / `.pcapng`: NetScope checks for `tshark.exe` in system PATH and standard Windows directories (`C:\Program Files\Wireshark\tshark.exe`). If found, it runs headless TShark extraction with structured field outputs. If missing, it uses native Scapy dissection.
   - For `.csv`: NetScope uses pandas with fuzzy column header matching (handling variations like `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`). If communication ports are not in dedicated columns, it reliably parses port arrows (e.g., `54122 -> 80`) from the Info column using regular expressions without inventing false values.
4. **Traffic Classification:**
   - **Confirmed HTTP:** Protocol header is `HTTP` or contains `GET /`, `POST /`, `HTTP/1.1`.
   - **Port-Inferred HTTP:** TCP packet on port 80 or 8080.
   - **Confirmed HTTPS/TLS:** Dissected `TLSv1.2`, `TLSv1.3`, `SSL`, or TLS Handshake frames (Client Hello with Server Name Indication).
   - **Port-Inferred HTTPS:** TCP control packet (SYN, ACK, FIN) on port 443 without payload inspection.
   - **QUIC (HTTP/3):** UDP packets on port 443 or dissected QUIC handshakes.
   - **DNS:** UDP/TCP port 53 or dissected DNS queries/responses.
5. **Statistical Aggregation:** Computes totals, averages, medians, MTU compliance, top talkers, and temporal packet rates.
6. **Visualization & Reporting:** Renders charts with Chart.js and allows one-click export of analyzed data into CSV or JSON.

---

## 8. Installation Instructions for Windows

### Step 1: Verify Python Installation
Open PowerShell and verify Python is installed:
```powershell
python --version
```
*(Python 3.9 or higher is recommended).*

### Step 2: (Optional but Recommended) Verify Wireshark / TShark
If you wish to analyze raw binary `.pcap` and `.pcapng` files directly, ensure Wireshark is installed:
- Download and install Wireshark from [https://www.wireshark.org/](https://www.wireshark.org/).
- Ensure the default installation path `C:\Program Files\Wireshark` is present. NetScope automatically detects TShark in this directory!
- *Note:* If Wireshark is not installed, NetScope still works completely for CSV files and utilizes Scapy as a fallback parser.

### Step 3: Install Required Dependencies
Navigate to the project root directory in PowerShell:
```powershell
cd c:\Users\patil\OneDrive\Desktop\NetScope_HTTP_HTTPS_Analyzer
python -m pip install -r requirements.txt
```

---

## 9. Wireshark Capture and CSV Export Instructions

### How to Capture Packets in Wireshark:
1. Launch **Wireshark** with administrator privileges.
2. Double-click your active internet interface (e.g., **Wi-Fi** or **Ethernet**).
3. In the top filter bar, enter a display/capture filter:
   ```
   tcp port 80 or tcp port 443 or udp port 53 or udp port 443
   ```
4. Open your web browser (Chrome, Edge, Firefox) and navigate to websites:
   - For cleartext HTTP: `http://neverssl.com` or `http://example.com`
   - For encrypted HTTPS: `https://github.com` or `https://cloudflare.com`
5. Return to Wireshark and click the red square button (**Stop Capturing Packets**).

### How to Save/Export Capture Files:
- **Option A: Save as Binary PCAPNG (Recommended)**
  - Click **File** &rarr; **Save As...**
  - Choose file name (e.g., `my_traffic.pcapng`) and save.
- **Option B: Export as CSV**
  - Click **File** &rarr; **Export Packet Dissections** &rarr; **As CSV...**
  - Ensure columns `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info` are included.
  - Save as `my_traffic.csv`.

---

## 10. How to Run the Application

In your PowerShell terminal:
```powershell
cd c:\Users\patil\OneDrive\Desktop\NetScope_HTTP_HTTPS_Analyzer
python app.py
```

You will see console output similar to:
```
============================================================
 NetScope — HTTP/HTTPS Traffic Analyzer
 Local Development Server Starting...
 [TShark Engine] TShark detected and ready (TShark (Wireshark) 4.6.9).
 URL: http://127.0.0.1:5000
============================================================
 * Running on http://127.0.0.1:5000
```

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 11. How to Use the Dashboard
1. **Overview Dashboard:** Review total packets, volume in bytes, detected protocols, capture duration, and mini charts.
2. **Upload & Analyze:** Drag and drop your `.pcap`, `.pcapng`, or `.csv` file. Click **Analyze Capture**.
3. **Load Sample Data:** For immediate evaluation or viva presentation without running Wireshark, click **Load Sample** in the top header or choose the built-in CSV/PCAP sample buttons.
4. **Packet Explorer:**
   - Filter by protocol (HTTP, TLS, QUIC, DNS, TCP, UDP).
   - Filter by classification category.
   - Use the real-time search box to find specific IP addresses or text strings.
   - Click column headers (e.g., *Length*, *Time*, *No.*) to sort ascending or descending.
   - Click the **Inspect** button on any row to open the full Packet Inspector modal.
5. **IP Address Analysis:** Observe top transmitting nodes, listening nodes, and active IP conversation pairs.
6. **Port & Transport:** Inspect communication ports and their mapped IANA services (e.g., Port 443 &rarr; HTTPS, Port 80 &rarr; HTTP, Port 53 &rarr; DNS).
7. **HTTP / TLS / QUIC:** Review the academic verification breakdown, detected TLS SNI hostnames, HTTP request verbs, and the cryptography explanation.
8. **Reports & Export:** Download analyzed packets as CSV, export statistics as CSV/JSON, or click **Print Report** for a clean, print-friendly academic document.

---

## 12. Example Results (Sample Data)
When loading the pre-packaged `sample_traffic.csv` demonstration trace, NetScope yields verifiable analytical results:
- **Total Packets:** 25 packets
- **Captured Volume:** 9,975 Bytes (~9.74 KB)
- **Minimum Packet Size:** 42 Bytes (ARP response)
- **Maximum Packet Size:** 1,420 Bytes (TLSv1.3 Server Hello & Application Data)
- **Mean Packet Size:** 399.00 Bytes
- **Median Packet Size:** 78.00 Bytes
- **Capture Duration:** 0.35 seconds
- **Protocol Classification Breakdown:**
  - HTTPS / TLSv1.3: 8 packets (32.0%)
  - HTTP (Cleartext): 7 packets (28.0%)
  - DNS: 4 packets (16.0%)
  - QUIC (HTTP/3): 3 packets (12.0%)
  - ARP: 2 packets (8.0%)
  - ICMP (Ping): 1 packet (4.0%)
- **Extracted TLS SNI Hostnames:** `api.github.com`
- **Extracted HTTP Verbs:** `GET` (1 request)
- **Verified Dissection vs Port Inference:**
  - HTTP: 2 dissected, 5 inferred (port 80 TCP handshake & ACKs)
  - HTTPS: 4 dissected TLS records, 4 inferred (port 443 TCP handshake & ACKs)
  - QUIC: 3 dissected QUIC packets

*(Note: These figures are generated from the labeled demo trace `sample_data/sample_traffic.csv` and do not mix with user-uploaded files).*

---

## 13. Testing Results & Verification Checklist

NetScope includes an automated test suite written with `pytest` in `tests/test_analyzer.py`.

### To run the automated tests:
```powershell
python -m pytest tests/test_analyzer.py
```

### Verified Test Cases:
| Test ID | Test Function | Purpose | Result |
| :---: | :--- | :--- | :---: |
| **TC-01** | `test_tshark_detection` | Verifies detection of TShark executable on host system. | **PASSED** |
| **TC-02** | `test_valid_csv_parsing` | Validates parsing of standard Wireshark CSV trace. | **PASSED** |
| **TC-03** | `test_missing_optional_columns` | Tests behavior when port, flag, or SNI columns are absent. | **PASSED** |
| **TC-04** | `test_empty_input_handling` | Ensures empty capture files do not cause division-by-zero errors. | **PASSED** |
| **TC-05** | `test_invalid_file_type` | Rejects non-capture files (e.g. `.txt`) with a clear error. | **PASSED** |
| **TC-06** | `test_protocol_statistics` | Verifies protocol count and percentage calculations sum to 100%. | **PASSED** |
| **TC-07** | `test_packet_size_calculations` | Verifies min, max, mean, and median using NumPy. | **PASSED** |
| **TC-08** | `test_missing_port_information` | Confirms missing ports are labeled `N/A` rather than fabricated. | **PASSED** |
| **TC-09** | `test_timestamp_parsing_and_duration` | Checks timestamp extraction and session duration calculation. | **PASSED** |
| **TC-10** | `test_export_functionality` | Tests generation of CSV and JSON export files on disk. | **PASSED** |
| **TC-11** | `test_port_extraction_patterns` | Verifies regex extraction of ports from Wireshark Info text. | **PASSED** |
| **TC-12** | `test_pcap_parsing` | Tests native dissection of binary `.pcap` files. | **PASSED** |
| **TC-13** | `test_flask_api_workflow` | End-to-end integration test of Flask API routes and downloads. | **PASSED** |

**Overall Test Execution: 13 passed in ~7.5 seconds (100% Pass Rate).**

---

## 14. Network Security & Cryptographic Awareness
A core learning outcome of this project is understanding network security boundaries:
- **Cleartext HTTP (Port 80):** Entire request methods, URLs, headers, and response HTML/JSON are transmitted in unencrypted plaintext across the network wire. Any intermediate router or observer can inspect and tamper with this data.
- **Encrypted HTTPS (Port 443) & QUIC (UDP 443):** Payloads are encrypted with authenticated symmetric ciphers (e.g., AES-GCM or ChaCha20-Poly1305) established during the TLS handshake.
- **What NetScope Can See:** Ethernet MAC addresses, IP addresses, communication ports, packet lengths, packet transmission timestamps, TCP flags, and the unencrypted TLS Server Name Indication (SNI) from the Client Hello.
- **What NetScope Cannot See (By Design):** Encrypted passwords, cookie tokens, or response HTML. NetScope strictly adheres to academic principles and does not attempt cryptographic bypass.

---

## 15. Limitations
1. **Encrypted Payload Inspection:** Application payload content inside TLS records cannot be viewed without providing pre-master secret key logs (`SSLKEYLOGFILE`).
2. **CSV Header Variance:** If a custom CSV file is exported from a non-Wireshark tool without standard IP or protocol headers, columns may be marked unavailable.
3. **Capture File Size:** The web interface enforces a 50 MB upload limit to prevent memory exhaustion on local development machines.

---

## 16. Future Enhancements
- Integration of live packet sniffing directly from Python using `scapy.all.sniff` or `pyshark.LiveCapture`.
- Decryption key log file (`SSLKEYLOGFILE`) upload to demonstrate authorized TLS payload decryption in academic lab environments.
- Automated anomaly detection for port scanning (SYN flood, FIN scans) and DNS tunneling.
- Geolocation mapping of public destination IP addresses using an offline MaxMind GeoLite2 database.

---

## 17. Conclusion
**NetScope** successfully fulfills all five Computer Networks academic objectives. By integrating real Wireshark capture processing, NumPy-powered metrics calculations, a Flask backend, and a modern dark navy dashboard, NetScope provides students and educators with an effective, practical, and beginner-friendly tool to study the mechanics of HTTP and HTTPS web traffic.
