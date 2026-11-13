
import random
import subprocess
import threading
import time
import uuid


LISTENER_SCRIPT = r"""
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8000))
server.listen(100)

while True:
    try:
        conn, address = server.accept()
        conn.close()
    except OSError:
        break
"""


WORKER_SCRIPT = r"""
import socket
import sys
import time

mode = sys.argv[1]
target = sys.argv[2]
count = int(sys.argv[3])
interval = float(sys.argv[4])


def connect(port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect_ex((target, port))
        sock.close()
    except OSError:
        pass


if mode == "normal":
    for _ in range(count):
        connect(8000)
        time.sleep(interval)

elif mode == "syn_burst":
    for _ in range(count):
        connect(8001)
        time.sleep(interval)

elif mode == "connection_burst":
    for _ in range(count):
        connect(8000)
        time.sleep(interval)

elif mode == "port_scan":
    for port in range(8100, 8100 + count):
        connect(port)
        time.sleep(interval)
"""


class TrafficGenerator:

    HOSTS = ["h1", "h2", "h3", "h4"]
    TARGET = "h5"

    SCENARIOS = {
        "normal": {},
        "syn_burst": {},
        "connection_burst": {},
        "port_scan": {},
        "mixed": {}
    }

    MODE_NAMES = {
        "normal": "Normal Traffic",
        "syn_burst": "TCP SYN Burst",
        "connection_burst": "TCP Connection Burst",
        "port_scan": "TCP Port Scan",
        "mixed": "Mixed Traffic"
    }

    PROFILES = {
        "LOW": {
            "syn": (21, 29),
            "connections": (10, 14)
        },
        "MEDIUM": {
            "syn": (30, 49),
            "connections": (15, 24)
        },
        "HIGH": {
            "syn": (50, 65),
            "connections": (25, 30)
        }
    }

    def __init__(self, net):
        self.net = net
        self.jobs = {}
        self.lock = threading.RLock()

    def choose_profile(self):
        name = random.choice(list(self.PROFILES.keys()))
        return name, self.PROFILES[name]

    def build_plan(self, mode):

        if mode == "normal":
            return [
                {
                    "mode": "normal",
                    "source": random.choice(self.HOSTS),
                    "count": 8,
                    "interval": 2.5,
                    "profile": "NORMAL"
                }
            ]

        if mode == "syn_burst":
            profile_name, profile = self.choose_profile()

            return [
                {
                    "mode": "syn_burst",
                    "source": random.choice(self.HOSTS),
                    "count": random.randint(*profile["syn"]),
                    "interval": random.uniform(0.08, 0.14),
                    "profile": profile_name
                }
            ]

        if mode == "connection_burst":
            profile_name, profile = self.choose_profile()

            return [
                {
                    "mode": "connection_burst",
                    "source": random.choice(self.HOSTS),
                    "count": random.randint(*profile["connections"]),
                    "interval": random.uniform(0.35, 0.75),
                    "profile": profile_name
                }
            ]

        if mode == "port_scan":
            return [
                {
                    "mode": "port_scan",
                    "source": random.choice(self.HOSTS),
                    "count": random.randint(9, 12),
                    "interval": random.uniform(0.1, 0.2),
                    "profile": "SCAN"
                }
            ]

        if mode == "mixed":
            sources = random.sample(self.HOSTS, 4)

            syn_name, syn_profile = self.choose_profile()
            connection_name, connection_profile = self.choose_profile()

            return [
                {
                    "mode": "normal",
                    "source": sources[0],
                    "count": 8,
                    "interval": 2.5,
                    "profile": "NORMAL"
                },
                {
                    "mode": "syn_burst",
                    "source": sources[1],
                    "count": random.randint(*syn_profile["syn"]),
                    "interval": random.uniform(0.08, 0.14),
                    "profile": syn_name
                },
                {
                    "mode": "connection_burst",
                    "source": sources[2],
                    "count": random.randint(*connection_profile["connections"]),
                    "interval": random.uniform(0.35, 0.75),
                    "profile": connection_name
                },
                {
                    "mode": "port_scan",
                    "source": sources[3],
                    "count": random.randint(9, 12),
                    "interval": random.uniform(0.1, 0.2),
                    "profile": "SCAN"
                }
            ]

        raise ValueError("Unsupported traffic scenario")

    def start(self, mode):

        if mode not in self.SCENARIOS:
            raise ValueError("Unsupported traffic scenario")

        with self.lock:

            if any(
                job["status"] == "running"
                for job in self.jobs.values()
            ):
                raise ValueError("Another traffic scenario is already running")

            plan = self.build_plan(mode)
            target = self.net.get(self.TARGET)

            if target is None:
                raise ValueError("Target host is unavailable")

            hosts = {
                item["source"]: self.net.get(item["source"])
                for item in plan
            }

            if any(host is None for host in hosts.values()):
                raise ValueError("Required Mininet hosts are unavailable")

            job_id = uuid.uuid4().hex[:8]
            processes = []
            workers = []

            listener = target.popen(
                ["python3", "-u", "-c", LISTENER_SCRIPT],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            processes.append(listener)
            time.sleep(0.3)

            try:
                for item in plan:
                    worker = hosts[item["source"]].popen(
                        [
                            "python3", "-u", "-c",
                            WORKER_SCRIPT,
                            item["mode"],
                            target.IP(),
                            str(item["count"]),
                            str(item["interval"])
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )

                    workers.append(worker)
                    processes.append(worker)

            except Exception:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                raise

            source_names = sorted({
                item["source"] for item in plan
            })

            intensity = "; ".join(
                f'{item["mode"]}: {item["profile"]} ({item["count"]})'
                for item in plan
            )

            self.jobs[job_id] = {
                "id": job_id,
                "mode": mode,
                "name": self.MODE_NAMES[mode],
                "source": ", ".join(source_names),
                "target": self.TARGET,
                "intensity": intensity,
                "status": "running",
                "started_at": time.time(),
                "processes": processes,
                "workers": workers
            }

            threading.Thread(
                target=self._monitor,
                args=(job_id,),
                daemon=True
            ).start()

            return self.get_job(job_id)

    def _monitor(self, job_id):

        while True:
            with self.lock:
                job = self.jobs.get(job_id)

                if job is None or job["status"] != "running":
                    return

                if all(
                    worker.poll() is not None
                    for worker in job["workers"]
                ):
                    for process in job["processes"]:
                        if process.poll() is None:
                            process.terminate()

                    job["status"] = "completed"
                    job["finished_at"] = time.time()
                    return

            time.sleep(0.5)

    def stop(self, job_id):

        with self.lock:
            job = self.jobs.get(job_id)

            if job is None:
                raise ValueError("Traffic job not found")

            if job["status"] == "running":
                for process in job["processes"]:
                    if process.poll() is None:
                        process.terminate()

                job["status"] = "stopped"
                job["finished_at"] = time.time()

            return self.get_job(job_id)

    def get_job(self, job_id):

        with self.lock:
            job = self.jobs.get(job_id)

            if job is None:
                return None

            return {
                key: value
                for key, value in job.items()
                if key not in ("processes", "workers")
            }

    def get_jobs(self):

        with self.lock:
            return [
                {
                    key: value
                    for key, value in job.items()
                    if key not in ("processes", "workers")
                }
                for job in self.jobs.values()
            ]

    def stop_all(self):

        with self.lock:
            for job in self.jobs.values():
                if job["status"] == "running":
                    for process in job["processes"]:
                        if process.poll() is None:
                            process.terminate()

                    job["status"] = "stopped"
                    job["finished_at"] = time.time()
