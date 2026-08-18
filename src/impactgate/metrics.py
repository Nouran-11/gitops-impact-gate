"""In-process Prometheus metrics. No extra dependency; text format is hand-rolled."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ANALYSIS_BUCKETS: tuple[float, ...] = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))
RECOVERY_BUCKETS: tuple[float, ...] = (10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, float("inf"))


def _le(bound: float) -> str:
    return "+Inf" if bound == float("inf") else f"{bound:g}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def clock(at: datetime | float | None = None) -> float:
    """Prefer an injected timestamp so tests can pin detection vs recovery."""
    if at is None:
        return time.monotonic()
    if isinstance(at, datetime):
        return at.timestamp()
    return at


class Histogram:
    def __init__(self, buckets: tuple[float, ...]) -> None:
        self.buckets = buckets
        self.counts = [0] * len(buckets)
        self.sum = 0.0
        self.count = 0

    def observe(self, value: float) -> None:
        self.sum += value
        self.count += 1
        for index, bound in enumerate(self.buckets):
            if value <= bound:
                self.counts[index] += 1

    def reset(self) -> None:
        self.counts = [0] * len(self.buckets)
        self.sum = 0.0
        self.count = 0

    def render(self, name: str, help_text: str) -> list[str]:
        lines = [
            f"# HELP {name} {help_text}",
            f"# TYPE {name} histogram",
        ]
        for bound, total in zip(self.buckets, self.counts, strict=True):
            lines.append(f'{name}_bucket{{le="{_le(bound)}"}} {total}')
        lines.append(f"{name}_sum {self.sum}")
        lines.append(f"{name}_count {self.count}")
        return lines


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._findings: dict[tuple[str, str, str], int] = defaultdict(int)
        self._gates: dict[str, int] = defaultdict(int)
        self._llm: dict[tuple[str, str], int] = defaultdict(int)
        self._remediation: dict[tuple[str, str], int] = defaultdict(int)
        self.analysis = Histogram(ANALYSIS_BUCKETS)
        self.recovery = Histogram(RECOVERY_BUCKETS)
        self._detected_at: dict[str, float] = {}

    def reset(self) -> None:
        with self._lock:
            self._findings.clear()
            self._gates.clear()
            self._llm.clear()
            self._remediation.clear()
            self.analysis.reset()
            self.recovery.reset()
            self._detected_at.clear()

    def record_finding(self, rule: str, severity: str, origin: str) -> None:
        with self._lock:
            self._findings[(rule, severity, origin)] += 1

    def record_gate(self, risk: str) -> None:
        with self._lock:
            self._gates[risk] += 1

    def record_llm(self, provider: str, *, cached: bool) -> None:
        with self._lock:
            self._llm[(provider, "true" if cached else "false")] += 1

    def record_analysis(self, seconds: float) -> None:
        with self._lock:
            self.analysis.observe(seconds)

    def record_remediation(self, action: str, outcome: str) -> None:
        with self._lock:
            self._remediation[(action, outcome)] += 1

    def note_detection(self, workload: str, at: datetime | float | None = None) -> None:
        """Start the MTTR clock at first detection. Later events must not reset it."""
        stamp = clock(at)
        with self._lock:
            self._detected_at.setdefault(workload, stamp)

    def note_recovery(self, workload: str, at: datetime | float | None = None) -> float | None:
        stamp = clock(at)
        with self._lock:
            started = self._detected_at.pop(workload, None)
            if started is None:
                return None
            elapsed = stamp - started
            self.recovery.observe(elapsed)
            return elapsed

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []
            lines.extend(
                [
                    "# HELP impactgate_findings_total Findings from graph analysis or scanners",
                    "# TYPE impactgate_findings_total counter",
                ]
            )
            if self._findings:
                for (rule, severity, origin), value in sorted(self._findings.items()):
                    lines.append(
                        "impactgate_findings_total{"
                        f'rule="{_escape(rule)}",severity="{_escape(severity)}",'
                        f'origin="{_escape(origin)}"}} {value}'
                    )

            lines.extend(
                [
                    "# HELP impactgate_gate_decisions_total Gate decisions by risk",
                    "# TYPE impactgate_gate_decisions_total counter",
                ]
            )
            if self._gates:
                for risk, value in sorted(self._gates.items()):
                    lines.append(
                        f'impactgate_gate_decisions_total{{risk="{_escape(risk)}"}} {value}'
                    )

            lines.extend(
                [
                    "# HELP impactgate_llm_calls_total LLM completions, including cache hits",
                    "# TYPE impactgate_llm_calls_total counter",
                ]
            )
            if self._llm:
                for (provider, cached), value in sorted(self._llm.items()):
                    lines.append(
                        "impactgate_llm_calls_total{"
                        f'provider="{_escape(provider)}",cached="{cached}"}} {value}'
                    )

            lines.extend(
                self.analysis.render(
                    "impactgate_analysis_duration_seconds",
                    "Wall time of one analyze run",
                )
            )
            lines.extend(
                [
                    "# HELP impactgate_remediation_total Controller actions by outcome",
                    "# TYPE impactgate_remediation_total counter",
                ]
            )
            if self._remediation:
                for (action, outcome), value in sorted(self._remediation.items()):
                    lines.append(
                        "impactgate_remediation_total{"
                        f'action="{_escape(action)}",outcome="{_escape(outcome)}"}} {value}'
                    )

            lines.extend(
                self.recovery.render(
                    "impactgate_time_to_recovery_seconds",
                    "Seconds from failure detection to all replicas ready",
                )
            )
            return "\n".join(lines) + "\n"


REGISTRY = MetricsRegistry()

_server_lock = threading.Lock()
_http_server: ThreadingHTTPServer | None = None
_http_thread: threading.Thread | None = None


class _MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path != "/metrics":
            self.send_error(404, "not found")
            return
        payload = REGISTRY.render().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def start_http_server(port: int = 8000, addr: str = "0.0.0.0") -> int:
    """Serve REGISTRY at GET /metrics. Returns the bound port (port 0 is ephemeral)."""
    global _http_server, _http_thread
    with _server_lock:
        if _http_server is not None:
            bound = int(_http_server.server_address[1])
            if port in (0, bound):
                return bound
            _stop_http_server_unlocked()
        server = ThreadingHTTPServer((addr, port), _MetricsHandler)
        thread = threading.Thread(
            target=server.serve_forever,
            name="impactgate-metrics",
            daemon=True,
        )
        thread.start()
        _http_server = server
        _http_thread = thread
        return int(server.server_address[1])


def stop_http_server() -> None:
    with _server_lock:
        _stop_http_server_unlocked()


def metrics_port() -> int | None:
    with _server_lock:
        if _http_server is None:
            return None
        return int(_http_server.server_address[1])


def _stop_http_server_unlocked() -> None:
    global _http_server, _http_thread
    server = _http_server
    thread = _http_thread
    _http_server = None
    _http_thread = None
    if server is None:
        return
    server.shutdown()
    server.server_close()
    if thread is not None:
        thread.join(timeout=2)

