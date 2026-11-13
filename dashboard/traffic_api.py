
import json
import urllib.error
import urllib.request

from flask import Blueprint, jsonify, request


traffic_api = Blueprint("traffic_api", __name__)

CONTROL_URL = "http://127.0.0.1:8765"

ALLOWED_SCENARIOS = {
    "normal",
    "syn_burst",
    "connection_burst",
    "port_scan",
    "mixed"
}


def control_request(path, method="GET", data=None):

    body = None
    headers = {}

    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        CONTROL_URL + path,
        data=body,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8")), response.status

    except urllib.error.HTTPError as error:
        try:
            result = json.loads(error.read().decode("utf-8"))
        except Exception:
            result = {"error": "Control server returned an error"}

        return result, error.code

    except (urllib.error.URLError, TimeoutError, OSError):
        return {
            "error": "Mininet traffic control is unavailable. Start the Mininet topology first."
        }, 503


@traffic_api.get("/api/traffic/status")
def traffic_status():

    result, status = control_request("/status")
    return jsonify(result), status


@traffic_api.post("/api/traffic/start")
def traffic_start():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request data"}), 400

    if set(data.keys()) != {"mode"}:
        return jsonify({
            "error": "Select one of the predefined traffic scenarios."
        }), 400

    mode = data.get("mode")

    if mode not in ALLOWED_SCENARIOS:
        return jsonify({"error": "Unsupported traffic scenario"}), 400

    result, status = control_request(
        "/start",
        "POST",
        {"mode": mode}
    )

    return jsonify(result), status


@traffic_api.post("/api/traffic/stop")
def traffic_stop():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request data"}), 400

    job_id = data.get("job_id")

    if not isinstance(job_id, str) or not job_id:
        return jsonify({"error": "Invalid job ID"}), 400

    result, status = control_request(
        "/stop",
        "POST",
        {"job_id": job_id}
    )

    return jsonify(result), status

