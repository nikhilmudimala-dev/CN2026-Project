
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from traffic.traffic_generator import TrafficGenerator


class ControlServer:

    def __init__(self, net, host="127.0.0.1", port=8765):
        self.generator = TrafficGenerator(net)
        self.server = None
        self.thread = None
        self.host = host
        self.port = port

    def start(self):

        generator = self.generator

        class Handler(BaseHTTPRequestHandler):

            def send_json(self, status, data):
                body = json.dumps(data).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    "Access-Control-Allow-Origin",
                    "http://127.0.0.1:5000"
                )
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):

                if self.path != "/status":
                    self.send_json(404, {"error": "Not found"})
                    return

                self.send_json(200, {
                    "available": True,
                    "scenarios": list(generator.SCENARIOS.keys()),
                    "jobs": generator.get_jobs()
                })

            def do_POST(self):

                if self.path not in ("/start", "/stop"):
                    self.send_json(404, {"error": "Not found"})
                    return

                try:
                    length = int(self.headers.get("Content-Length", "0"))

                    if length <= 0 or length > 4096:
                        self.send_json(
                            400,
                            {"error": "Invalid request size"}
                        )
                        return

                    data = json.loads(
                        self.rfile.read(length).decode("utf-8")
                    )

                    if not isinstance(data, dict):
                        self.send_json(400, {"error": "Invalid request"})
                        return

                    if self.path == "/start":

                        if set(data.keys()) != {"mode"}:
                            self.send_json(
                                400,
                                {"error": "Only a predefined scenario mode is accepted"}
                            )
                            return

                        job = generator.start(data.get("mode"))

                        self.send_json(200, {
                            "success": True,
                            "job": job
                        })

                    else:

                        job_id = data.get("job_id")

                        if not isinstance(job_id, str):
                            self.send_json(
                                400,
                                {"error": "Invalid job ID"}
                            )
                            return

                        job = generator.stop(job_id)

                        self.send_json(200, {
                            "success": True,
                            "job": job
                        })

                except (ValueError, KeyError) as error:
                    self.send_json(400, {"error": str(error)})

                except Exception as error:
                    self.send_json(500, {"error": str(error)})

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(
            (self.host, self.port),
            Handler
        )

        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True
        )

        self.thread.start()

        print(
            f"*** Traffic control server running at "
            f"http://{self.host}:{self.port}"
        )

    def stop(self):

        self.generator.stop_all()

        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None

        print("*** Traffic control server stopped")

