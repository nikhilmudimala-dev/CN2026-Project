
const TRAFFIC_API = "/api/traffic";

const SCENARIO_NAMES = {
    normal: "Normal Traffic",
    syn_burst: "TCP SYN Burst",
    connection_burst: "TCP Connection Burst",
    port_scan: "TCP Port Scan",
    mixed: "Mixed Traffic"
};

let trafficAvailable = false;
let trafficJobs = [];
let trafficRequestInProgress = false;


async function trafficRequest(path, method = "GET", data = null) {

    const options = {
        method,
        headers: {}
    };

    if (data !== null) {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(data);
    }

    const response = await fetch(TRAFFIC_API + path, options);

    let result;

    try {
        result = await response.json();
    } catch {
        throw new Error("Invalid response from traffic server.");
    }

    if (!response.ok) {
        throw new Error(result.error || "Traffic request failed.");
    }

    return result;
}


function setTrafficMessage(message, isError = false) {

    const element = document.getElementById("traffic-message");

    if (!element) return;

    element.textContent = message;
    element.classList.toggle("traffic-error", isError);
}


function setTrafficStatus(available) {

    trafficAvailable = available;

    const dot = document.getElementById("traffic-status-dot");
    const text = document.getElementById("traffic-status-text");

    if (dot) {
        dot.className = available ? "traffic-online" : "traffic-offline";
    }

    if (text) {
        text.textContent = available
            ? "Mininet traffic control connected"
            : "Mininet traffic control unavailable";
    }

    updateScenarioButtons();
}


function updateScenarioButtons() {

    const running = trafficJobs.some(job => job.status === "running");

    document.querySelectorAll(".scenario-button").forEach(button => {
        button.disabled =
            !trafficAvailable ||
            running ||
            trafficRequestInProgress;
    });
}


function renderTrafficJobs(jobs) {

    const tbody = document.getElementById("traffic-jobs-body");

    if (!tbody) return;

    tbody.replaceChildren();

    if (!jobs || jobs.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.textContent = "No traffic jobs yet.";

        row.appendChild(cell);
        tbody.appendChild(row);
        return;
    }

    [...jobs].reverse().forEach(job => {

        const row = document.createElement("tr");

        const values = [
            job.id,
            job.name || SCENARIO_NAMES[job.mode] || job.mode,
            job.source,
            job.target,
            job.status
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value ?? "—";
            row.appendChild(cell);
        });

        const actionCell = document.createElement("td");

        if (job.status === "running") {

            const stopButton = document.createElement("button");

            stopButton.textContent = "Stop";
            stopButton.className = "traffic-job-stop";
            stopButton.addEventListener("click", () => {
                stopTrafficJob(job.id);
            });

            actionCell.appendChild(stopButton);

        } else {
            actionCell.textContent = "—";
        }

        row.appendChild(actionCell);
        tbody.appendChild(row);
    });
}


async function loadTrafficStatus() {

    try {

        const result = await trafficRequest("/status");

        trafficJobs = result.jobs || [];

        setTrafficStatus(result.available === true);
        renderTrafficJobs(trafficJobs);

        const running = trafficJobs.some(
            job => job.status === "running"
        );

        if (running) {
            setTrafficMessage("A traffic scenario is currently running.");
        } else {
            setTrafficMessage("Ready to launch a traffic scenario.");
        }

    } catch (error) {

        trafficJobs = [];

        setTrafficStatus(false);
        renderTrafficJobs([]);

        setTrafficMessage(error.message, true);
    }

    updateScenarioButtons();
}


async function startTrafficScenario(mode) {

    if (!SCENARIO_NAMES[mode]) return;

    if (!trafficAvailable || trafficRequestInProgress) return;

    trafficRequestInProgress = true;
    updateScenarioButtons();

    setTrafficMessage(
        "Starting " + SCENARIO_NAMES[mode] + "..."
    );

    try {

        const result = await trafficRequest(
            "/start",
            "POST",
            { mode }
        );

        setTrafficMessage(
            SCENARIO_NAMES[mode] + " started successfully."
        );

        await loadTrafficStatus();

    } catch (error) {

        setTrafficMessage(error.message, true);

    } finally {

        trafficRequestInProgress = false;
        updateScenarioButtons();
    }
}


async function stopTrafficJob(jobId) {

    if (!jobId || trafficRequestInProgress) return;

    trafficRequestInProgress = true;
    updateScenarioButtons();

    setTrafficMessage("Stopping traffic job " + jobId + "...");

    try {

        await trafficRequest(
            "/stop",
            "POST",
            { job_id: jobId }
        );

        setTrafficMessage("Traffic job stopped successfully.");

        await loadTrafficStatus();

    } catch (error) {

        setTrafficMessage(error.message, true);

    } finally {

        trafficRequestInProgress = false;
        updateScenarioButtons();
    }
}


document.addEventListener("DOMContentLoaded", () => {

    document.querySelectorAll(".scenario-button").forEach(button => {

        button.addEventListener("click", () => {
            startTrafficScenario(button.dataset.scenario);
        });

    });

    loadTrafficStatus();

    setInterval(loadTrafficStatus, 3000);
});

