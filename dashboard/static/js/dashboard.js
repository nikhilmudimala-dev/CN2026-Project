
let ruleChart = null;
let monitorChart = null;
let currentConfig = null;

const $ = id => document.getElementById(id);

async function api(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;",
        '"': "&quot;", "'": "&#39;"
    })[char]);
}

function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? escapeHTML(value) :
        date.toLocaleString();
}

function eventPill(type) {
    const css = type === "ALERT" ? "alert" :
        type === "BAN_EXPIRED" ? "expired" : "";
    return `<span class="event-pill ${css}">${escapeHTML(type)}</span>`;
}

function fillEventTable(target, rows, compact = false) {
    const element = $(target);

    if (!rows.length) {
        element.innerHTML = `<tr><td colspan="7" class="empty">No recorded events yet.</td></tr>`;
        return;
    }

    element.innerHTML = rows.map(event => compact
        ? `<tr>
            <td>${eventPill(event.event_type)}</td>
            <td class="ip">${escapeHTML(event.source_ip || "—")}</td>
            <td>${escapeHTML(event.rule_id || "—")}</td>
            <td title="${escapeHTML(event.message)}">${escapeHTML(event.message || "—")}</td>
            <td>${formatTime(event.timestamp)}</td>
          </tr>`
        : `<tr>
            <td>${escapeHTML(event.id)}</td>
            <td>${eventPill(event.event_type)}</td>
            <td class="ip">${escapeHTML(event.source_ip || "—")}</td>
            <td>${escapeHTML(event.rule_id || "—")}</td>
            <td>${escapeHTML(event.severity || "—")}</td>
            <td title="${escapeHTML(event.message)}">${escapeHTML(event.message || "—")}</td>
            <td>${formatTime(event.timestamp)}</td>
          </tr>`
    ).join("");
}

function chartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: "#9aabc0", usePointStyle: true, padding: 20 }
            }
        },
        scales: {
            x: { ticks: { color: "#8193aa" }, grid: { color: "#243149" } },
            y: {
                beginAtZero: true,
                ticks: { color: "#8193aa", precision: 0 },
                grid: { color: "#243149" }
            }
        }
    };
}

function updateCharts(counts) {
    const labels = ["R1 · SYN Rate", "R2 · Connection Burst", "R3 · Port Scan"];
    const values = [
        counts.R1_SYN_RATE || 0,
        counts.R2_CONNECTION_BURST || 0,
        counts.R3_PORT_SCAN || 0
    ];

    const colors = ["#548cff", "#a78bfa", "#f4a261"];

    if (ruleChart) ruleChart.destroy();
    ruleChart = new Chart($("ruleChart"), {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: "#111b2b",
                borderWidth: 5,
                hoverOffset: 7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: "#9aabc0", padding: 16, usePointStyle: true }
                }
            }
        }
    });

    if (monitorChart) monitorChart.destroy();
    monitorChart = new Chart($("monitorChart"), {
        type: "bar",
        data: {
            labels: ["R1 · SYN Rate", "R2 · Connection Burst", "R3 · Port Scan"],
            datasets: [{
                label: "Recorded detections",
                data: values,
                backgroundColor: colors,
                borderRadius: 6,
                maxBarThickness: 65
            }]
        },
        options: chartOptions()
    });
}

function updateRuleCounts(events) {
    const counts = {
        R1_SYN_RATE: 0,
        R2_CONNECTION_BURST: 0,
        R3_PORT_SCAN: 0
    };

    events.forEach(event => {
        if (event.event_type === "DETECTION" || event.event_type === "ALERT") {
            if (event.rule_id in counts) counts[event.rule_id]++;
        }
    });

    $("r1-count").textContent = counts.R1_SYN_RATE;
    $("r2-count").textContent = counts.R2_CONNECTION_BURST;
    $("r3-count").textContent = counts.R3_PORT_SCAN;
}

async function loadOverview() {
    const data = await api("/api/overview");

    $("hosts-count").textContent = data.hosts;
    $("switch-count").textContent = data.switches;
    $("detection-count").textContent = data.detections;
    $("ban-count").textContent = data.active_bans;
    $("event-count").textContent = data.total_events;
    $("incident-count").textContent = data.blocking_incidents;
    $("alert-count").textContent = data.alerts;
    $("observed-count").textContent = data.observed_hosts;

    const counts = {};
    data.rule_counts.forEach(row => counts[row.rule_id] = row.total);
    updateCharts(counts);

    fillEventTable("recent-events", data.recent_events, true);
    $("last-updated").textContent =
        "Updated " + new Date().toLocaleTimeString();

    return data;
}

async function loadEvents() {
    const rows = await api("/api/events?limit=100");
    fillEventTable("event-table", rows);
    fillEventTable("monitor-events", rows.filter(
        row => row.event_type === "DETECTION" || row.event_type === "ALERT"
    ), true);
    updateRuleCounts(rows);
}

async function loadBans() {
    const [bans, incidents] = await Promise.all([
        api("/api/bans"),
        api("/api/incidents")
    ]);

    $("ban-table").innerHTML = bans.length ? bans.map(ban => `
        <tr>
            <td class="ip">${escapeHTML(ban.source_ip)}</td>
            <td>${escapeHTML(ban.rule_id)}</td>
            <td>${escapeHTML(ban.severity)}</td>
            <td>${ban.offence_count}</td>
            <td>${ban.remaining_seconds > 0
                ? ban.remaining_seconds + " seconds"
                : "Expiry pending"}</td>
        </tr>
    `).join("") : `<tr><td colspan="5" class="empty">No active ban records.</td></tr>`;

    $("incident-table").innerHTML = incidents.length ? incidents.map(item => `
        <tr>
            <td class="ip">${escapeHTML(item.source_ip)}</td>
            <td>${escapeHTML(item.rule_id)}</td>
            <td>${escapeHTML(item.severity)}</td>
            <td>${item.offence_count}</td>
            <td>${item.ban_duration_seconds}s</td>
        </tr>
    `).join("") : `<tr><td colspan="5" class="empty">No incidents recorded.</td></tr>`;
}

async function loadRules() {
    currentConfig = await api("/api/rules");

    const rules = [
        ["syn_rate", "r1"],
        ["connection_burst", "r2"],
        ["port_scan", "r3"]
    ];

    rules.forEach(([key, prefix]) => {
        const rule = currentConfig.rules[key];

        $(prefix + "-threshold").textContent = rule.threshold;
        $(prefix + "-window").textContent = rule.window_seconds + "s";
    });

    $("config-fields").innerHTML = rules.map(([key, prefix]) => {
        const rule = currentConfig.rules[key];
        const title = {
            syn_rate: "R1 · SYN rate threshold",
            connection_burst: "R2 · Connection threshold",
            port_scan: "R3 · Port scan threshold"
        }[key];

        return `
            <div class="config-field">
                <label>${title}</label>
                <input type="number" min="1" id="${prefix}-edit-threshold"
                    value="${rule.threshold}">
                <label style="margin-top:12px">Window (seconds)</label>
                <input type="number" min="1" id="${prefix}-edit-window"
                    value="${rule.window_seconds}">
            </div>`;
    }).join("");
}

async function saveRules() {
    try {
        const rules = currentConfig.rules;

        [
            ["syn_rate", "r1"],
            ["connection_burst", "r2"],
            ["port_scan", "r3"]
        ].forEach(([key, prefix]) => {
            rules[key].threshold = Number($(`${prefix}-edit-threshold`).value);
            rules[key].window_seconds = Number($(`${prefix}-edit-window`).value);
        });

        const result = await api("/api/rules", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(currentConfig)
        });

        $("config-message").textContent =
            "Configuration saved. Restart the controller to apply changes.";
        $("config-message").className = "";
        await loadRules();
    } catch (error) {
        $("config-message").textContent = error.message;
        $("config-message").className = "error";
    }
}

async function loadTopology() {
    const data = await api("/api/topology");

    data.access_switches.forEach(switchName => {
        const hosts = data.hosts.filter(host => host.switch === switchName);
        $("hosts-" + switchName).innerHTML = hosts.map(host => `
            <div class="host-node">
                <strong>${escapeHTML(host.name)}</strong>
                <small>${escapeHTML(host.ip)}</small>
            </div>
        `).join("");
    });
}

function navigate(page) {
    document.querySelectorAll(".page").forEach(section =>
        section.classList.toggle("active", section.id === page)
    );

    document.querySelectorAll(".nav-link").forEach(link =>
        link.classList.toggle("active", link.dataset.page === page)
    );

    const names = {
        overview: "Security Overview",
        topology: "Network Topology",
        monitoring: "Traffic Monitoring",
        rules: "Detection Rules",
        bans: "Blocked Hosts",
        events: "Event Logs"
    };

    $("page-title").textContent = names[page] || names.overview;
    $("page-name").textContent = (page || "overview").toUpperCase();
    history.replaceState(null, "", "#" + page);
}

document.querySelectorAll(".nav-link").forEach(link => {
    link.addEventListener("click", event => {
        event.preventDefault();
        navigate(link.dataset.page);
    });
});

$("save-rules").addEventListener("click", saveRules);
$("refresh-events").addEventListener("click", loadEvents);

function updateClock() {
    $("clock").textContent = new Date().toLocaleTimeString();
}

async function refreshDashboard() {
    try {
        await Promise.all([
            loadOverview(),
            loadEvents(),
            loadBans()
        ]);
    } catch (error) {
        console.error("Dashboard refresh failed:", error);
    }
}

async function initialize() {
    updateClock();
    setInterval(updateClock, 1000);

    try {
        await Promise.all([
            loadTopology(),
            loadRules(),
            refreshDashboard()
        ]);

        const initialPage = location.hash.replace("#", "");
        if (document.getElementById(initialPage)?.classList.contains("page")) {
            navigate(initialPage);
        }
    } catch (error) {
        console.error("Dashboard initialization failed:", error);
        $("last-updated").textContent = "Database connection error";
    }

    setInterval(refreshDashboard, 5000);
}

initialize();
