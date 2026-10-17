/**
 * NetScope — HTTP/HTTPS Traffic Analyzer
 * Frontend Application Controller: Chart.js visualization, SPA navigation,
 * asynchronous file uploads, packet table pagination, filtering, and inspector modal.
 */

document.addEventListener("DOMContentLoaded", () => {
    // -------------------------------------------------------------
    // Application State
    // -------------------------------------------------------------
    const state = {
        activeView: "overview-view",
        currentAnalysis: null,
        isSample: false,
        tsharkAvailable: false,
        pagination: {
            page: 1,
            pageSize: 25,
            totalPages: 1,
            totalFiltered: 0,
            totalPackets: 0
        },
        filters: {
            search: "",
            protocol: "ALL",
            category: "ALL",
            port: ""
        },
        sorting: {
            sortBy: "no",
            sortDir: "asc"
        },
        charts: {}
    };

    // View descriptions map
    const viewMeta = {
        "overview-view": { title: "Overview Dashboard", subtext: "Real-time network traffic telemetry and packet analysis" },
        "upload-view": { title: "Upload & Analyze Traffic", subtext: "Process PCAP, PCAPNG, or Wireshark-exported CSV traces" },
        "explorer-view": { title: "Packet Explorer Table", subtext: "Inspect individual frames, transport flags, and protocol headers" },
        "ip-analysis-view": { title: "IP Address Analysis", subtext: "Endpoint telemetry, top talkers, and network conversations" },
        "port-analysis-view": { title: "Port & Transport Layer", subtext: "Server endpoints, ephemeral client ports, and service identification" },
        "web-analysis-view": { title: "HTTP / TLS / QUIC Analysis", subtext: "Web protocol verification, SNI hostnames, and payload encryption audit" },
        "protocols-view": { title: "Protocol Statistics", subtext: "Complete protocol breakdown, data volume, and category ratios" },
        "size-analysis-view": { title: "Packet Size & MTU Analysis", subtext: "Payload size distributions and Ethernet MTU histogram" },
        "time-analysis-view": { title: "Traffic Activity Timeline", subtext: "Temporal traffic density and session transmission rates" },
        "reports-view": { title: "Reports & Export", subtext: "Download analyzed packet records, JSON telemetry, and printable audits" },
        "about-view": { title: "About Project & Objectives", subtext: "Academic requirements, system architecture, and verification matrix" }
    };

    // -------------------------------------------------------------
    // DOM Element References
    // -------------------------------------------------------------
    const navItems = document.querySelectorAll(".nav-item");
    const viewPanels = document.querySelectorAll(".view-panel");
    const currentHeading = document.getElementById("currentViewHeading");
    const currentSubtext = document.getElementById("currentViewSubtext");
    const sidebar = document.getElementById("sidebar");
    const mobileNavToggle = document.getElementById("mobileNavToggle");

    // Action buttons
    const btnQuickSample = document.getElementById("btnQuickSample");
    const btnQuickUpload = document.getElementById("btnQuickUpload");
    const btnPrintReport = document.getElementById("btnPrintReport");
    const sampleDataAlert = document.getElementById("sampleDataAlert");
    const btnCloseSampleAlert = document.getElementById("btnCloseSampleAlert");
    const statusDot = document.getElementById("statusDot");
    const statusLabel = document.getElementById("statusLabel");
    const statusDetails = document.getElementById("statusDetails");
    const sampleDataBadge = document.getElementById("sampleDataBadge");

    // Upload & Dropzone
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");
    const selectedFileBox = document.getElementById("selectedFileBox");
    const selectedFileName = document.getElementById("selectedFileName");
    const selectedFileSize = document.getElementById("selectedFileSize");
    const btnStartAnalysis = document.getElementById("btnStartAnalysis");
    const btnCancelFile = document.getElementById("btnCancelFile");
    const uploadProgressContainer = document.getElementById("uploadProgressContainer");
    const uploadProgressFill = document.getElementById("uploadProgressFill");
    const uploadProgressText = document.getElementById("uploadProgressText");
    const sampleChoiceBtns = document.querySelectorAll(".btn-sample-choice");

    // Explorer elements
    const packetSearchInput = document.getElementById("packetSearchInput");
    const filterProtocol = document.getElementById("filterProtocol");
    const filterCategory = document.getElementById("filterCategory");
    const pageSizeSelect = document.getElementById("pageSizeSelect");
    const btnResetFilters = document.getElementById("btnResetFilters");
    const packetTableBody = document.getElementById("packetTableBody");
    const filteredCountText = document.getElementById("filteredCountText");
    const paginationInfo = document.getElementById("paginationInfo");
    const pageNumbersWrap = document.getElementById("pageNumbersWrap");
    const btnPageFirst = document.getElementById("btnPageFirst");
    const btnPagePrev = document.getElementById("btnPagePrev");
    const btnPageNext = document.getElementById("btnPageNext");
    const btnPageLast = document.getElementById("btnPageLast");

    // Inspector Modal
    const packetModal = document.getElementById("packetModal");
    const modalPacketTitle = document.getElementById("modalPacketTitle");
    const modalPacketSubtitle = document.getElementById("modalPacketSubtitle");
    const modalPacketBody = document.getElementById("modalPacketBody");
    const btnCloseModal = document.getElementById("btnCloseModal");
    const btnModalCloseAction = document.getElementById("btnModalCloseAction");

    let currentSelectedFile = null;

    // -------------------------------------------------------------
    // Notification Toast Helper
    // -------------------------------------------------------------
    function showToast(message, duration = 3500) {
        const toast = document.getElementById("toastNotification");
        toast.textContent = message;
        toast.classList.remove("hidden");
        setTimeout(() => {
            toast.classList.add("hidden");
        }, duration);
    }

    // -------------------------------------------------------------
    // Format Utility Functions
    // -------------------------------------------------------------
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function getProtocolBadgeClass(proto) {
        const p = (proto || "").toUpperCase();
        if (p.includes("HTTP/3") || p.includes("QUIC")) return "badge-amber";
        if (p.includes("TLS") || p.includes("SSL") || p.includes("HTTPS")) return "badge-purple";
        if (p.includes("HTTP")) return "badge-green";
        if (p.includes("DNS")) return "badge-cyan";
        if (p.includes("TCP")) return "badge-blue";
        if (p.includes("UDP")) return "badge-indigo";
        if (p.includes("ARP") || p.includes("ICMP")) return "badge-rose";
        return "badge-outline";
    }

    function getCategoryBadgeClass(cat) {
        switch (cat) {
            case "HTTP": return "badge-green";
            case "HTTPS/TLS": return "badge-purple";
            case "QUIC": return "badge-amber";
            case "DNS": return "badge-cyan";
            case "TCP": return "badge-blue";
            case "UDP": return "badge-indigo";
            default: return "badge-outline";
        }
    }

    // -------------------------------------------------------------
    // SPA View Switching
    // -------------------------------------------------------------
    function switchView(viewId) {
        viewPanels.forEach(panel => {
            panel.classList.toggle("active", panel.id === viewId);
        });
        navItems.forEach(item => {
            item.classList.toggle("active", item.getAttribute("data-view") === viewId);
        });

        state.activeView = viewId;
        if (viewMeta[viewId]) {
            currentHeading.textContent = viewMeta[viewId].title;
            currentSubtext.textContent = viewMeta[viewId].subtext;
        }

        // Close sidebar on mobile
        sidebar.classList.remove("open");

        // Trigger chart resize when view becomes visible
        window.dispatchEvent(new Event("resize"));
    }

    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const viewId = item.getAttribute("data-view");
            if (viewId) switchView(viewId);
        });
    });

    if (mobileNavToggle) {
        mobileNavToggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });
    }

    btnQuickUpload.addEventListener("click", () => switchView("upload-view"));
    btnQuickSample.addEventListener("click", () => loadSampleDataset("csv"));
    btnPrintReport.addEventListener("click", () => window.print());
    btnCloseSampleAlert.addEventListener("click", () => sampleDataAlert.classList.add("hidden"));

    // -------------------------------------------------------------
    // Chart Management Helpers (Using Chart.js)
    // -------------------------------------------------------------
    function destroyChart(name) {
        if (state.charts[name]) {
            state.charts[name].destroy();
            delete state.charts[name];
        }
    }

    const chartColors = [
        "#06b6d4", "#a855f7", "#38bdf8", "#10b981", "#f59e0b",
        "#6366f1", "#ec4899", "#f43f5e", "#8b5cf6", "#14b8a6"
    ];

    function renderProtocolDoughnut(protoCounts) {
        destroyChart("protoDoughnut");
        const canvas = document.getElementById("chartProtocolDoughnut");
        if (!canvas) return;

        const labels = Object.keys(protoCounts || {});
        const data = Object.values(protoCounts || {});

        if (labels.length === 0) {
            labels.push("No Data");
            data.push(1);
        }

        state.charts.protoDoughnut = new Chart(canvas, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: chartColors.slice(0, labels.length),
                    borderWidth: 2,
                    borderColor: "#141e33"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "right",
                        labels: { color: "#cbd5e1", font: { size: 11 } }
                    }
                },
                cutout: "65%"
            }
        });
    }

    function renderWebTrafficBar(categories) {
        destroyChart("webTrafficBar");
        const canvas = document.getElementById("chartWebTrafficBar");
        if (!canvas) return;

        const webCategories = ["HTTP", "HTTPS/TLS", "QUIC", "DNS"];
        const counts = webCategories.map(cat => (categories && categories[cat]) ? categories[cat] : 0);

        state.charts.webTrafficBar = new Chart(canvas, {
            type: "bar",
            data: {
                labels: ["HTTP (Cleartext)", "HTTPS/TLS (Encrypted)", "QUIC (HTTP/3)", "DNS"],
                datasets: [{
                    label: "Packets Captured",
                    data: counts,
                    backgroundColor: ["#10b981", "#a855f7", "#f59e0b", "#06b6d4"],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { ticks: { color: "#94a3b8", font: { size: 11 } }, grid: { display: false } },
                    y: { ticks: { color: "#94a3b8", font: { size: 11 } }, grid: { color: "#202d4a" } }
                }
            }
        });
    }

    function renderTrafficTimeLine(timeData) {
        destroyChart("trafficTime");
        const canvas = document.getElementById("chartTrafficTime");
        if (!canvas) return;

        const labels = timeData && timeData.labels && timeData.labels.length > 0 ? timeData.labels : ["0s"];
        const packetCounts = timeData && timeData.packet_counts ? timeData.packet_counts : [0];

        state.charts.trafficTime = new Chart(canvas, {
            type: "line",
            data: {
                labels: labels,
                datasets: [{
                    label: "Packets per Interval",
                    data: packetCounts,
                    borderColor: "#38bdf8",
                    backgroundColor: "rgba(56, 189, 248, 0.1)",
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 3,
                    pointBackgroundColor: "#38bdf8"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { display: false } },
                    y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#202d4a" }, beginAtZero: true }
                }
            }
        });
    }

    function renderSizeHistogram(sizeDist) {
        destroyChart("sizeHistogram");
        const canvas = document.getElementById("chartSizeHistogram");
        if (!canvas) return;

        const labels = sizeDist && sizeDist.labels ? sizeDist.labels : ["< 128 B", "128-511 B", "512-1023 B", "1024-1514 B", "> 1514 B"];
        const counts = sizeDist && sizeDist.counts ? sizeDist.counts : [0, 0, 0, 0, 0];

        state.charts.sizeHistogram = new Chart(canvas, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Packets in Range",
                    data: counts,
                    backgroundColor: "#3b82f6",
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { display: false } },
                    y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#202d4a" }, beginAtZero: true }
                }
            }
        });
    }

    function renderTopIPCharts(topSrc, topDst) {
        destroyChart("topSrcIP");
        destroyChart("topDstIP");

        const canvasSrc = document.getElementById("chartTopSrcIP");
        const canvasDst = document.getElementById("chartTopDstIP");

        if (canvasSrc) {
            const labels = (topSrc || []).map(item => item.ip);
            const data = (topSrc || []).map(item => item.count);

            state.charts.topSrcIP = new Chart(canvasSrc, {
                type: "bar",
                data: {
                    labels: labels.length ? labels : ["None"],
                    datasets: [{
                        label: "Packets Sent",
                        data: data.length ? data : [0],
                        backgroundColor: "#38bdf8",
                        borderRadius: 5
                    }]
                },
                options: {
                    indexAxis: "y",
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: "#94a3b8" }, grid: { color: "#202d4a" }, beginAtZero: true },
                        y: { ticks: { color: "#cbd5e1" }, grid: { display: false } }
                    }
                }
            });
        }

        if (canvasDst) {
            const labels = (topDst || []).map(item => item.ip);
            const data = (topDst || []).map(item => item.count);

            state.charts.topDstIP = new Chart(canvasDst, {
                type: "bar",
                data: {
                    labels: labels.length ? labels : ["None"],
                    datasets: [{
                        label: "Packets Received",
                        data: data.length ? data : [0],
                        backgroundColor: "#06b6d4",
                        borderRadius: 5
                    }]
                },
                options: {
                    indexAxis: "y",
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: "#94a3b8" }, grid: { color: "#202d4a" }, beginAtZero: true },
                        y: { ticks: { color: "#cbd5e1" }, grid: { display: false } }
                    }
                }
            });
        }
    }

    function renderPortCharts(topSrcPorts, topDstPorts) {
        destroyChart("topSrcPorts");
        destroyChart("topDstPorts");

        const canvasSrc = document.getElementById("chartTopSrcPorts");
        const canvasDst = document.getElementById("chartTopDstPorts");

        if (canvasSrc) {
            const labels = (topSrcPorts || []).map(p => `Port ${p.port}`);
            const data = (topSrcPorts || []).map(p => p.count);

            state.charts.topSrcPorts = new Chart(canvasSrc, {
                type: "bar",
                data: {
                    labels: labels.length ? labels : ["N/A"],
                    datasets: [{
                        label: "Source Port Packets",
                        data: data.length ? data : [0],
                        backgroundColor: "#818cf8",
                        borderRadius: 5
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
                        y: { ticks: { color: "#94a3b8" }, grid: { color: "#202d4a" }, beginAtZero: true }
                    }
                }
            });
        }

        if (canvasDst) {
            const labels = (topDstPorts || []).map(p => `Port ${p.port}`);
            const data = (topDstPorts || []).map(p => p.count);

            state.charts.topDstPorts = new Chart(canvasDst, {
                type: "bar",
                data: {
                    labels: labels.length ? labels : ["N/A"],
                    datasets: [{
                        label: "Destination Port Packets",
                        data: data.length ? data : [0],
                        backgroundColor: "#a855f7",
                        borderRadius: 5
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
                        y: { ticks: { color: "#94a3b8" }, grid: { color: "#202d4a" }, beginAtZero: true }
                    }
                }
            });
        }
    }

    // -------------------------------------------------------------
    // Populate Dashboard Data
    // -------------------------------------------------------------
    function updateDashboardUI(stats, filename, isSample) {
        state.isSample = isSample;
        state.currentAnalysis = stats;

        // Update Sidebar Status
        statusDot.classList.add("active");
        statusLabel.textContent = isSample ? "Sample Dataset" : "Active Capture";
        statusDetails.textContent = filename || "Capture loaded";
        if (isSample) {
            sampleDataBadge.classList.remove("hidden");
            sampleDataAlert.classList.remove("hidden");
        } else {
            sampleDataBadge.classList.add("hidden");
            sampleDataAlert.classList.add("hidden");
        }

        // Overview KPI Cards
        document.getElementById("kpiTotalPackets").textContent = stats.total_packets.toLocaleString();
        document.getElementById("kpiWebPackets").textContent = `${stats.web_traffic_summary.total_web_packets.toLocaleString()} web packets (HTTP/TLS/QUIC)`;
        document.getElementById("kpiTotalBytes").textContent = formatBytes(stats.total_bytes);
        document.getElementById("kpiAvgSize").textContent = `Mean: ${stats.mean_packet_size} B / Median: ${stats.median_packet_size} B`;
        
        const protoCount = Object.keys(stats.protocol_counts || {}).length;
        document.getElementById("kpiProtocolCount").textContent = protoCount;
        document.getElementById("badgeTotalProtocols").textContent = `${protoCount} Protocols`;

        const topProto = Object.entries(stats.protocol_counts || {}).sort((a,b) => b[1]-a[1])[0];
        document.getElementById("kpiTopProtocol").textContent = topProto ? `Dominant: ${topProto[0]} (${topProto[1]})` : "Dominant: None";

        document.getElementById("kpiDuration").textContent = stats.duration_formatted;
        document.getElementById("kpiDurationRange").textContent = stats.timestamps_available ? `${stats.start_time} → ${stats.end_time}` : "Relative offsets";

        // Web traffic share badge
        const webShare = stats.total_packets > 0 ? ((stats.web_traffic_summary.total_web_packets / stats.total_packets) * 100).toFixed(1) : 0;
        document.getElementById("badgeWebTrafficShare").textContent = `${webShare}% Web Traffic`;

        // Render Charts
        renderProtocolDoughnut(stats.protocol_counts);
        renderWebTrafficBar(stats.category_counts);
        renderTrafficTimeLine(stats.traffic_over_time);
        renderSizeHistogram(stats.size_distribution);
        renderTopIPCharts(stats.top_source_ips, stats.top_destination_ips);
        renderPortCharts(stats.top_source_ports, stats.top_destination_ports);

        // Populate Overview Talkers Tables
        populateOverviewTalkers(stats.top_source_ips, stats.top_destination_ips);

        // Populate IP Conversations Table
        populateIPPairs(stats.top_ip_pairs, stats.total_packets);

        // Populate Port Mapping Table
        populatePortDetails(stats.top_destination_ports, stats.top_source_ports);

        // Populate Protocol Statistics Table
        populateProtocolStats(stats);

        // Populate Size Bins
        populateSizeMetrics(stats);

        // Populate Time Metrics
        populateTimeMetrics(stats);

        // Populate Web Deep Dive & Verification
        populateWebAnalysis(stats);

        // Populate Unavailable Fields List
        populateUnavailableFields(stats.unavailable_fields);

        // Populate Protocol Filter Select Options
        populateProtocolFilter(stats.protocol_counts);

        // Load First Page of Explorer Packets
        fetchPackets();
    }

    function populateOverviewTalkers(topSrc, topDst) {
        const srcTbody = document.querySelector("#tableOverviewSrcIP tbody");
        const dstTbody = document.querySelector("#tableOverviewDstIP tbody");

        if (srcTbody) {
            if (!topSrc || topSrc.length === 0) {
                srcTbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No source IPs detected.</td></tr>`;
            } else {
                srcTbody.innerHTML = topSrc.map(item => `
                    <tr>
                        <td><code>${item.ip}</code></td>
                        <td><strong>${item.count.toLocaleString()}</strong></td>
                        <td>${formatBytes(item.bytes)}</td>
                        <td><span class="badge badge-blue">${item.percentage}%</span></td>
                    </tr>
                `).join("");
            }
        }

        if (dstTbody) {
            if (!topDst || topDst.length === 0) {
                dstTbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No destination IPs detected.</td></tr>`;
            } else {
                dstTbody.innerHTML = topDst.map(item => `
                    <tr>
                        <td><code>${item.ip}</code></td>
                        <td><strong>${item.count.toLocaleString()}</strong></td>
                        <td>${formatBytes(item.bytes)}</td>
                        <td><span class="badge badge-cyan">${item.percentage}%</span></td>
                    </tr>
                `).join("");
            }
        }
    }

    function populateIPPairs(pairs, totalPackets) {
        const tbody = document.querySelector("#tableIPPairs tbody");
        const badge = document.getElementById("badgeTotalPairs");
        if (!tbody) return;

        if (!pairs || pairs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No active conversation pairs.</td></tr>`;
            if (badge) badge.textContent = "0 Conversations";
            return;
        }

        if (badge) badge.textContent = `${pairs.length} Conversations`;
        tbody.innerHTML = pairs.map(p => {
            const pct = totalPackets > 0 ? ((p.count / totalPackets) * 100).toFixed(1) : 0;
            return `
                <tr>
                    <td><code>${p.pair}</code></td>
                    <td><strong>${p.count.toLocaleString()}</strong></td>
                    <td>${formatBytes(p.bytes)}</td>
                    <td><span class="badge badge-emerald">${pct}%</span></td>
                </tr>
            `;
        }).join("");
    }

    function populatePortDetails(dstPorts, srcPorts) {
        const tbody = document.querySelector("#tablePortDetails tbody");
        if (!tbody) return;

        const allPorts = [];
        (dstPorts || []).forEach(p => allPorts.push({ ...p, dir: "Inbound / Server" }));
        (srcPorts || []).forEach(p => allPorts.push({ ...p, dir: "Outbound / Client" }));

        if (allPorts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Port information is unavailable in this capture file.</td></tr>`;
            return;
        }

        allPorts.sort((a,b) => b.count - a.count);
        tbody.innerHTML = allPorts.slice(0, 15).map(p => `
            <tr>
                <td><strong>Port ${p.port}</strong></td>
                <td><span class="badge badge-purple">${p.service}</span></td>
                <td>${p.dir}</td>
                <td>${p.count.toLocaleString()}</td>
                <td>${p.percentage}%</td>
            </tr>
        `).join("");
    }

    function populateProtocolStats(stats) {
        const tbody = document.querySelector("#tableProtocolStats tbody");
        if (!tbody) return;

        const protos = Object.keys(stats.protocol_counts || {});
        if (protos.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No protocols detected.</td></tr>`;
            return;
        }

        tbody.innerHTML = protos.map(proto => {
            const count = stats.protocol_counts[proto];
            const pct = stats.protocol_percentages[proto] || 0;
            const b = stats.protocol_bytes[proto] || 0;
            const avg = count > 0 ? Math.round(b / count) : 0;
            const isEnc = ["TLS", "SSL", "QUIC"].some(k => proto.toUpperCase().includes(k));
            const badgeClass = getProtocolBadgeClass(proto);

            return `
                <tr>
                    <td><span class="badge ${badgeClass}">${proto}</span></td>
                    <td>${stats.category_counts[proto] ? proto : "Transport/App"}</td>
                    <td><strong>${count.toLocaleString()}</strong></td>
                    <td>${pct}%</td>
                    <td>${formatBytes(b)}</td>
                    <td>${avg} B</td>
                    <td>${isEnc ? '<span class="badge badge-purple">🔒 Encrypted</span>' : '<span class="badge badge-outline">Cleartext / Header</span>'}</td>
                </tr>
            `;
        }).join("");
    }

    function populateSizeMetrics(stats) {
        document.getElementById("sizeMin").textContent = `${stats.min_packet_size} B`;
        document.getElementById("sizeMax").textContent = `${stats.max_packet_size} B`;
        document.getElementById("sizeMean").textContent = `${stats.mean_packet_size} B`;
        document.getElementById("sizeMedian").textContent = `${stats.median_packet_size} B`;

        if (stats.size_distribution && stats.size_distribution.counts) {
            for (let i = 0; i < 5; i++) {
                const cnt = stats.size_distribution.counts[i] || 0;
                const pct = stats.size_distribution.percentages[i] || 0;
                const countEl = document.getElementById(`bin${i+1}Count`);
                const pctEl = document.getElementById(`bin${i+1}Pct`);
                if (countEl) countEl.textContent = cnt.toLocaleString();
                if (pctEl) pctEl.textContent = `${pct}%`;
            }
        }
    }

    function populateTimeMetrics(stats) {
        document.getElementById("timeStart").textContent = stats.start_time || "0.000000s";
        document.getElementById("timeEnd").textContent = stats.end_time || `${stats.duration_seconds}s`;
        document.getElementById("timeDuration").textContent = stats.duration_formatted;
        
        const rate = (stats.duration_seconds > 0) ? (stats.total_packets / stats.duration_seconds).toFixed(1) : stats.total_packets;
        document.getElementById("timePktRate").textContent = `${rate} pkts/sec`;
    }

    function populateWebAnalysis(stats) {
        const v = stats.verification_breakdown || {};
        document.getElementById("verifHttpConfirmed").textContent = v.http_confirmed || 0;
        document.getElementById("verifHttpInferred").textContent = v.http_inferred || 0;
        document.getElementById("verifHttpsConfirmed").textContent = v.https_confirmed || 0;
        document.getElementById("verifHttpsInferred").textContent = v.https_inferred || 0;
        document.getElementById("verifQuicConfirmed").textContent = v.quic_confirmed || 0;
        document.getElementById("verifQuicInferred").textContent = v.quic_inferred || 0;

        // TLS SNI List
        const sniList = document.getElementById("sniList");
        const domains = stats.web_traffic_summary.tls_domains || [];
        if (domains.length === 0) {
            sniList.innerHTML = `<li class="text-muted">No TLS Server Name Indication (SNI) records detected in capture.</li>`;
        } else {
            sniList.innerHTML = domains.map(d => `<li class="sni-item">🔒 ${d}</li>`).join("");
        }

        // HTTP Methods
        const methodGrid = document.getElementById("httpMethodsGrid");
        const methods = stats.web_traffic_summary.http_methods || {};
        const methodKeys = Object.keys(methods);
        if (methodKeys.length === 0) {
            methodGrid.innerHTML = `<div class="text-muted">No cleartext HTTP request verbs found in capture.</div>`;
        } else {
            methodGrid.innerHTML = methodKeys.map(m => `
                <div class="http-method-pill">
                    <span class="http-method-name">${m}</span>
                    <span class="http-method-count">${methods[m]}</span>
                </div>
            `).join("");
        }
    }

    function populateUnavailableFields(unavailable) {
        const list = document.getElementById("unavailableList");
        if (!list) return;

        if (!unavailable || unavailable.length === 0) {
            list.innerHTML = `<li class="text-emerald">✓ All standard network fields (IPs, Ports, Timestamps, Flags) were successfully extracted!</li>`;
        } else {
            list.innerHTML = unavailable.map(item => `<li>⚠️ <strong>${item}</strong></li>`).join("");
        }
    }

    function populateProtocolFilter(protoCounts) {
        if (!filterProtocol) return;
        const currentVal = filterProtocol.value;
        const protos = Object.keys(protoCounts || {});

        let html = `<option value="ALL">All Protocols</option>`;
        protos.forEach(p => {
            html += `<option value="${p}">${p} (${protoCounts[p]})</option>`;
        });
        filterProtocol.innerHTML = html;
        if (protos.includes(currentVal)) {
            filterProtocol.value = currentVal;
        }
    }

    // -------------------------------------------------------------
    // Packet Explorer Table (Pagination, Filtering, Sorting)
    // -------------------------------------------------------------
    async function fetchPackets() {
        const params = new URLSearchParams({
            page: state.pagination.page,
            page_size: state.pagination.pageSize,
            search: state.filters.search,
            protocol: state.filters.protocol,
            category: state.filters.category,
            sort_by: state.sorting.sortBy,
            sort_dir: state.sorting.sortDir
        });

        try {
            const res = await fetch(`/api/packets?${params.toString()}`);
            const data = await res.json();
            if (data.success) {
                renderPacketTable(data);
            }
        } catch (err) {
            console.error("Failed to load packets:", err);
        }
    }

    function renderPacketTable(data) {
        state.pagination.page = data.page;
        state.pagination.pageSize = data.page_size;
        state.pagination.totalPages = data.total_pages;
        state.pagination.totalFiltered = data.total_filtered;
        state.pagination.totalPackets = data.total_packets;

        filteredCountText.textContent = `Showing ${data.packets.length} of ${data.total_filtered.toLocaleString()} packets (Total: ${data.total_packets.toLocaleString()})`;
        paginationInfo.textContent = `Page ${data.page} of ${data.total_pages || 1}`;

        // Render Page Number Buttons
        renderPaginationButtons();

        if (!data.packets || data.packets.length === 0) {
            packetTableBody.innerHTML = `<tr><td colspan="12" class="text-center text-muted">No packets matching your current filter criteria.</td></tr>`;
            return;
        }

        packetTableBody.innerHTML = data.packets.map(p => {
            const protoBadge = getProtocolBadgeClass(p.protocol);
            const catBadge = getCategoryBadgeClass(p.traffic_category);
            const lockIcon = p.is_encrypted ? "🔒 " : "";

            return `
                <tr>
                    <td><strong>#${p.no}</strong></td>
                    <td>${p.time_str}</td>
                    <td><code>${p.src_ip}</code></td>
                    <td>${p.src_port !== null ? p.src_port : '<span class="text-muted">N/A</span>'}</td>
                    <td><code>${p.dst_ip}</code></td>
                    <td>${p.dst_port !== null ? p.dst_port : '<span class="text-muted">N/A</span>'}</td>
                    <td><span class="badge ${protoBadge}">${p.protocol}</span></td>
                    <td>${p.length} B</td>
                    <td>${p.tcp_flags ? `<code class="code-pill">${p.tcp_flags}</code>` : '<span class="text-muted">—</span>'}</td>
                    <td><span class="badge ${catBadge}">${lockIcon}${p.traffic_category}</span></td>
                    <td title="${p.info}">${p.info}</td>
                    <td>
                        <button class="btn btn-outline btn-inspect" data-no="${p.no}" style="padding: 3px 8px; font-size: 11px;">
                            Inspect
                        </button>
                    </td>
                </tr>
            `;
        }).join("");

        // Attach Inspect Click Listeners
        document.querySelectorAll(".btn-inspect").forEach(btn => {
            btn.addEventListener("click", () => {
                const packetNo = btn.getAttribute("data-no");
                openPacketInspector(packetNo);
            });
        });
    }

    function renderPaginationButtons() {
        const { page, totalPages } = state.pagination;
        btnPageFirst.disabled = (page <= 1);
        btnPagePrev.disabled = (page <= 1);
        btnPageNext.disabled = (page >= totalPages);
        btnPageLast.disabled = (page >= totalPages);

        pageNumbersWrap.innerHTML = "";
        const maxButtons = 5;
        let startPage = Math.max(1, page - Math.floor(maxButtons / 2));
        let endPage = Math.min(totalPages, startPage + maxButtons - 1);
        if (endPage - startPage + 1 < maxButtons) {
            startPage = Math.max(1, endPage - maxButtons + 1);
        }

        for (let i = startPage; i <= endPage; i++) {
            const btn = document.createElement("button");
            btn.className = `btn-page ${i === page ? 'active' : ''}`;
            btn.textContent = i;
            btn.addEventListener("click", () => {
                state.pagination.page = i;
                fetchPackets();
            });
            pageNumbersWrap.appendChild(btn);
        }
    }

    btnPageFirst.addEventListener("click", () => { state.pagination.page = 1; fetchPackets(); });
    btnPagePrev.addEventListener("click", () => { state.pagination.page = Math.max(1, state.pagination.page - 1); fetchPackets(); });
    btnPageNext.addEventListener("click", () => { state.pagination.page = Math.min(state.pagination.totalPages, state.pagination.page + 1); fetchPackets(); });
    btnPageLast.addEventListener("click", () => { state.pagination.page = state.pagination.totalPages; fetchPackets(); });

    // Table Header Sorting
    document.querySelectorAll(".packet-table th.sortable").forEach(th => {
        th.addEventListener("click", () => {
            const sortField = th.getAttribute("data-sort");
            if (state.sorting.sortBy === sortField) {
                state.sorting.sortDir = (state.sorting.sortDir === "asc") ? "desc" : "asc";
            } else {
                state.sorting.sortBy = sortField;
                state.sorting.sortDir = "asc";
            }
            fetchPackets();
        });
    });

    // Explorer Filters Listeners
    let searchDebounce = null;
    packetSearchInput.addEventListener("input", (e) => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
            state.filters.search = e.target.value.trim();
            state.pagination.page = 1;
            fetchPackets();
        }, 300);
    });

    filterProtocol.addEventListener("change", (e) => {
        state.filters.protocol = e.target.value;
        state.pagination.page = 1;
        fetchPackets();
    });

    filterCategory.addEventListener("change", (e) => {
        state.filters.category = e.target.value;
        state.pagination.page = 1;
        fetchPackets();
    });

    pageSizeSelect.addEventListener("change", (e) => {
        state.pagination.pageSize = parseInt(e.target.value);
        state.pagination.page = 1;
        fetchPackets();
    });

    btnResetFilters.addEventListener("click", () => {
        packetSearchInput.value = "";
        filterProtocol.value = "ALL";
        filterCategory.value = "ALL";
        pageSizeSelect.value = "25";
        state.filters.search = "";
        state.filters.protocol = "ALL";
        state.filters.category = "ALL";
        state.pagination.pageSize = 25;
        state.pagination.page = 1;
        fetchPackets();
    });

    // -------------------------------------------------------------
    // Packet Inspector Modal
    // -------------------------------------------------------------
    async function openPacketInspector(packetNo) {
        try {
            const res = await fetch(`/api/packet/${packetNo}`);
            const data = await res.json();
            if (!data.success) {
                showToast("Could not retrieve packet details.");
                return;
            }

            const p = data.packet;
            modalPacketTitle.textContent = `Packet Inspector #${p.no}`;
            modalPacketSubtitle.textContent = `Protocol: ${p.protocol} • Length: ${p.length} Bytes`;

            modalPacketBody.innerHTML = `
                <div class="inspector-grid">
                    <div class="inspector-row">
                        <div class="inspector-label">Timestamp / Time Offset</div>
                        <div class="inspector-val">${p.time_str}</div>
                    </div>
                    <div class="inspector-row">
                        <div class="inspector-label">Traffic Classification</div>
                        <div class="inspector-val"><span class="badge ${getCategoryBadgeClass(p.traffic_category)}">${p.traffic_category}</span></div>
                    </div>
                    <div class="inspector-row">
                        <div class="inspector-label">Source Endpoint</div>
                        <div class="inspector-val"><code>${p.src_ip}</code> : <strong>${p.src_port !== null ? p.src_port : 'N/A'}</strong></div>
                    </div>
                    <div class="inspector-row">
                        <div class="inspector-label">Destination Endpoint</div>
                        <div class="inspector-val"><code>${p.dst_ip}</code> : <strong>${p.dst_port !== null ? p.dst_port : 'N/A'}</strong></div>
                    </div>
                    <div class="inspector-row">
                        <div class="inspector-label">Identification Method</div>
                        <div class="inspector-val">${p.identification_type}</div>
                    </div>
                    <div class="inspector-row">
                        <div class="inspector-label">Payload Encryption</div>
                        <div class="inspector-val">${p.is_encrypted ? '🔒 Protected by TLS / QUIC' : '🔓 Cleartext / Transport Header'}</div>
                    </div>
                    <div class="inspector-row">
                        <div class="inspector-label">TCP Control Flags</div>
                        <div class="inspector-val">${p.tcp_flags ? `<code>${p.tcp_flags}</code>` : 'None / Not Applicable'}</div>
                    </div>
                    <div class="inspector-row">
                        <div class="inspector-label">Server Name Indication (SNI)</div>
                        <div class="inspector-val">${p.tls_sni ? `<code>${p.tls_sni}</code>` : 'N/A'}</div>
                    </div>
                </div>

                <div class="inspector-label mb-2">Packet Informational Summary</div>
                <div class="inspector-info-box">${p.info}</div>

                <div class="academic-note-box">
                    <strong>Academic Explanation:</strong> ${p.notes}
                </div>
            `;

            packetModal.classList.remove("hidden");
        } catch (err) {
            console.error(err);
            showToast("Error inspecting packet.");
        }
    }

    btnCloseModal.addEventListener("click", () => packetModal.classList.add("hidden"));
    btnModalCloseAction.addEventListener("click", () => packetModal.classList.add("hidden"));
    packetModal.addEventListener("click", (e) => {
        if (e.target === packetModal) packetModal.classList.add("hidden");
    });

    // -------------------------------------------------------------
    // File Upload Handling
    // -------------------------------------------------------------
    function handleFileSelection(file) {
        if (!file) return;
        const validExts = [".pcap", ".pcapng", ".cap", ".csv"];
        const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
        if (!validExts.includes(ext)) {
            showToast(`Unsupported file format '${ext}'. Allowed: .pcap, .pcapng, .csv`);
            return;
        }

        if (file.size > 50 * 1024 * 1024) {
            showToast("File size exceeds 50 MB limit.");
            return;
        }

        currentSelectedFile = file;
        selectedFileName.textContent = file.name;
        selectedFileSize.textContent = formatBytes(file.size);
        selectedFileBox.classList.remove("hidden");
        dropzone.classList.add("hidden");
    }

    dropzone.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files[0]) {
            handleFileSelection(e.target.files[0]);
        }
    });

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileSelection(e.dataTransfer.files[0]);
        }
    });

    btnCancelFile.addEventListener("click", () => {
        currentSelectedFile = null;
        fileInput.value = "";
        selectedFileBox.classList.add("hidden");
        dropzone.classList.remove("hidden");
    });

    btnStartAnalysis.addEventListener("click", async () => {
        if (!currentSelectedFile) return;

        uploadProgressContainer.classList.remove("hidden");
        uploadProgressFill.style.width = "40%";
        uploadProgressText.textContent = "Dissecting packets with NetScope Engine...";
        btnStartAnalysis.disabled = true;

        const formData = new FormData();
        formData.append("file", currentSelectedFile);

        try {
            uploadProgressFill.style.width = "75%";
            const res = await fetch("/api/upload", {
                method: "POST",
                body: formData
            });

            const data = await res.json();
            uploadProgressFill.style.width = "100%";

            if (data.success) {
                showToast(`Success! Analyzed ${data.stats.total_packets} packets from ${data.filename}.`);
                updateDashboardUI(data.stats, data.filename, false);
                switchView("overview-view");
                // Reset file selection
                btnCancelFile.click();
            } else {
                showToast(`Analysis Failed: ${data.error}`);
            }
        } catch (err) {
            console.error(err);
            showToast("Server error during packet upload and processing.");
        } finally {
            uploadProgressContainer.classList.add("hidden");
            uploadProgressFill.style.width = "0%";
            btnStartAnalysis.disabled = false;
        }
    });

    // -------------------------------------------------------------
    // Sample Dataset Loader
    // -------------------------------------------------------------
    async function loadSampleDataset(format = "csv") {
        showToast(`Loading demo trace (${format.toUpperCase()})...`);
        try {
            const res = await fetch("/api/load-sample", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ format: format })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                updateDashboardUI(data.stats, data.filename, true);
                switchView("overview-view");
            } else {
                showToast(`Failed: ${data.error}`);
            }
        } catch (err) {
            console.error(err);
            showToast("Network error loading sample dataset.");
        }
    }

    sampleChoiceBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const fmt = btn.getAttribute("data-format");
            loadSampleDataset(fmt);
        });
    });

    // -------------------------------------------------------------
    // Initial Environment Check & Boot
    // -------------------------------------------------------------
    async function initializeApp() {
        try {
            const res = await fetch("/api/status");
            const data = await res.json();
            if (data.success) {
                state.tsharkAvailable = data.tshark.available;
                if (data.active_analysis && data.active_analysis.loaded) {
                    // Fetch already loaded analysis
                    const statsRes = await fetch("/api/statistics");
                    const statsData = await statsRes.json();
                    if (statsData.success) {
                        updateDashboardUI(statsData.stats, statsData.filename, statsData.is_sample);
                        return;
                    }
                }
            }
        } catch (err) {
            console.warn("Could not query initial status:", err);
        }

        // Automatically load demo CSV on first launch for immediate visual verification
        loadSampleDataset("csv");
    }

    initializeApp();
});
