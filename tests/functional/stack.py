"""Own an isolated local PostgreSQL, Python scorer, and compiled Go API."""

import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import httpx


ROOT = Path(__file__).resolve().parents[2]


def command(args, **kwargs):
    result = subprocess.run(
        [str(arg) for arg in args], text=True, capture_output=True,
        timeout=60, **kwargs,
    )
    if result.returncode:
        raise RuntimeError(f"Command failed: {args[0]}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def postgres_bin():
    configured = os.environ.get("PG_BINDIR")
    candidates = [Path(configured)] if configured else []
    if shutil.which("pg_config"):
        candidates.append(Path(command(["pg_config", "--bindir"])))
    candidates.extend([Path("/opt/homebrew/opt/postgresql@16/bin"),
                       Path("/usr/local/opt/postgresql@16/bin")])
    for candidate in candidates:
        if all((candidate / tool).is_file() for tool in ("initdb", "postgres", "pg_ctl", "psql")):
            return candidate
    raise RuntimeError("Install PostgreSQL and set PG_BINDIR to its bin directory.")


class Stack:
    def __init__(self, directory, binary, model):
        self.directory = directory
        self.binary = binary
        self.model = model
        self.dns_server = ""
        self.pg_bin = postgres_bin()
        self.data = directory / "pgdata"
        # Short socket path avoids PostgreSQL's Unix socket path length limit.
        self.socket_dir = Path(tempfile.mkdtemp(prefix="tg-stack-", dir="/tmp"))
        self.pg_port = free_port()
        self.api_port = free_port()
        self.model_port = free_port()
        self.processes = {}
        self.logs = {}
        self.client = httpx.Client(timeout=15, trust_env=False)
        self.api_url = f"http://127.0.0.1:{self.api_port}"
        self.model_url = f"http://127.0.0.1:{self.model_port}"

    def launch(self, name, args, extra_env=None):
        if name in self.processes:
            raise RuntimeError(f"{name} is already started")
        log = (self.directory / f"{name}.log").open("ab")
        self.logs[name] = log
        try:
            self.processes[name] = subprocess.Popen(
                [str(arg) for arg in args], cwd=ROOT,
                env={**os.environ, **(extra_env or {})},
                stdout=log, stderr=subprocess.STDOUT,
            )
        except BaseException:
            log.close()
            del self.logs[name]
            raise

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process is not None:
            if process.poll() is None:
                # PostgreSQL fast shutdown closes pooled connections and flushes disk.
                process.send_signal(signal.SIGINT if name == "postgres" else signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            self.logs.pop(name).close()

    def wait_http(self, name, url):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.processes[name].poll() is not None:
                break
            try:
                if self.client.get(url, timeout=.5).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            time.sleep(.1)
        log = (self.directory / f"{name}.log").read_text(errors="replace")
        raise RuntimeError(f"{name} did not become ready at {url}\n{log[-8000:]}")

    def sql(self, statement, database="threatgraph_stack"):
        return command([
            self.pg_bin / "psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
            "-h", self.socket_dir, "-p", self.pg_port, "-U", "stack_admin",
            "-d", database, "-c", statement,
        ])

    def start_postgres(self):
        self.launch("postgres", [
            self.pg_bin / "postgres", "-D", self.data, "-h", "",
            "-k", self.socket_dir, "-p", self.pg_port,
        ])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                self.sql("SELECT 1", database="postgres")
                return
            except RuntimeError:
                if self.processes["postgres"].poll() is not None:
                    break
                time.sleep(.1)
        raise RuntimeError("Temporary PostgreSQL cluster did not become ready")

    def start_model(self):
        self.launch("model", [
            sys.executable, "-m", "uvicorn", "ml.src.threatgraph_ml.scoring_api:app",
            "--host", "127.0.0.1", "--port", self.model_port,
        ], {"THREATGRAPH_BRAND_MODEL_PATH": str(self.model)})
        self.wait_http("model", self.model_url + "/healthz")

    def start_api(self):
        self.launch("api", [self.binary], {
            "PORT": str(self.api_port), "SCORER_URL": self.model_url,
            "DNS_SERVER": self.dns_server, "DNS_LOOKUP_TIMEOUT": "250ms",
            "DNS_CACHE_TTL": "5m", "DNS_NEGATIVE_CACHE_TTL": "30s",
            "DATABASE_URL": (
                f"host={self.socket_dir} port={self.pg_port} "
                "user=threatgraph_app dbname=threatgraph_stack sslmode=disable"
            ),
        })
        self.wait_http("api", self.api_url + "/readyz")

    def start(self):
        command([self.pg_bin / "initdb", "-D", self.data, "-U", "stack_admin",
                 "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"])
        self.start_postgres()
        self.sql("CREATE ROLE threatgraph_app LOGIN", database="postgres")
        self.sql("CREATE DATABASE threatgraph_stack OWNER threatgraph_app", database="postgres")
        self.start_model()
        self.start_api()

    def close(self):
        try:
            for name in ("api", "model", "postgres"):
                self.stop(name)
        finally:
            self.client.close()
            shutil.rmtree(self.socket_dir)

    def get(self, path):
        return self.client.get(self.api_url + path)

    def create(self, **overrides):
        payload = {
            "candidate_url": "https://acme-review.test/login",
            "brand_name": "Acme", "brand_domain": "acme.example",
            **overrides,
        }
        return self.client.post(self.api_url + "/v1/analyses", json=payload)
