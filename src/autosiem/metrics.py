"""Metrics primitives and Prometheus text exposition for AutoSIEM.

Implements a small, dependency-free metrics toolkit (counter / gauge /
histogram) plus a registry and a ``prometheus_text`` serializer that produces
deterministic ``text/plain`` output. Also provides lightweight tracing via
``Span``/``Trace`` context managers.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator
from uuid import uuid4

# Prometheus-compatible default histogram buckets (seconds).
DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def _num(value: Any) -> str:
    """Render a numeric value in Prometheus text form."""
    f = float(value)
    if f.is_integer():
        return str(int(f))
    return repr(f)


def _escape(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt_labels(labels: dict[str, Any]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


class Counter:
    """A monotonically increasing counter."""

    def __init__(self, name: str, labels: dict[str, Any] | None = None) -> None:
        self.name = name
        self.labels: dict[str, Any] = dict(labels or {})
        self._value = 0.0

    def inc(self, value: float = 1) -> None:
        self._value += value

    @property
    def value(self) -> float:
        return self._value


class Gauge:
    """A value that can go up and down."""

    def __init__(self, name: str, labels: dict[str, Any] | None = None) -> None:
        self.name = name
        self.labels: dict[str, Any] = dict(labels or {})
        self._value = 0.0

    def set(self, value: float) -> None:
        self._value = value

    def inc(self, value: float = 1) -> None:
        self._value += value

    def dec(self, value: float = 1) -> None:
        self._value -= value

    @property
    def value(self) -> float:
        return self._value


class Histogram:
    """A histogram over a fixed set of cumulative buckets."""

    def __init__(
        self,
        name: str,
        labels: dict[str, Any] | None = None,
        buckets: tuple[float, ...] | list[float] | None = None,
    ) -> None:
        self.name = name
        self.labels: dict[str, Any] = dict(labels or {})
        self.buckets: tuple[float, ...] = (
            tuple(buckets) if buckets is not None else DEFAULT_BUCKETS
        )
        self._counts: dict[float, int] = {b: 0 for b in self.buckets}
        self._sum = 0.0
        self._count = 0

    def observe(self, value: float) -> None:
        self._count += 1
        self._sum += max(0.0, value)
        for bound in self.buckets:
            if value <= bound:
                self._counts[bound] += 1

    def bucket_counts(self) -> list[int]:
        """Cumulative observation count for each bucket bound, in order."""
        return [self._counts[b] for b in self.buckets]

    @property
    def sum(self) -> float:
        return self._sum

    @property
    def count(self) -> int:
        return self._count


class MetricsRegistry:
    """Holds metrics keyed by ``(name, labels)``."""

    def __init__(self) -> None:
        self._counters: dict[tuple[Any, ...], Counter] = {}
        self._gauges: dict[tuple[Any, ...], Gauge] = {}
        self._histograms: dict[tuple[Any, ...], Histogram] = {}

    @staticmethod
    def _key(name: str, labels: dict[str, Any]) -> tuple[Any, ...]:
        return (name, tuple(sorted(labels.items())))

    def counter(self, name: str, **labels: Any) -> Counter:
        key = self._key(name, labels)
        if key not in self._counters:
            self._counters[key] = Counter(name, labels)
        return self._counters[key]

    def gauge(self, name: str, **labels: Any) -> Gauge:
        key = self._key(name, labels)
        if key not in self._gauges:
            self._gauges[key] = Gauge(name, labels)
        return self._gauges[key]

    def histogram(self, name: str, **labels: Any) -> Histogram:
        key = self._key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = Histogram(name, labels)
        return self._histograms[key]

    def all_metrics(self) -> list[Any]:
        return (
            list(self._counters.values())
            + list(self._gauges.values())
            + list(self._histograms.values())
        )


def prometheus_text(registry: MetricsRegistry) -> str:
    """Render every metric in Prometheus ``text/plain`` format (deterministic)."""
    lines: list[str] = []

    for metric in sorted(
        registry.all_metrics(), key=lambda m: (m.name, sorted(m.labels.items()))
    ):
        labels = dict(metric.labels)
        if isinstance(metric, Histogram):
            name = metric.name
            for i, bound in enumerate(metric.buckets):
                blabels = dict(labels)
                blabels["le"] = _num(bound)
                lines.append(f"{name}_bucket{_fmt_labels(blabels)} {metric.bucket_counts()[i]}")
            inf_labels = dict(labels)
            inf_labels["le"] = "+Inf"
            lines.append(f"{name}_bucket{_fmt_labels(inf_labels)} {metric.count}")
            lines.append(f"{name}_sum{_fmt_labels(labels)} {_num(metric.sum)}")
            lines.append(f"{name}_count{_fmt_labels(labels)} {metric.count}")
        else:
            lines.append(f"{metric.name}{_fmt_labels(labels)} {_num(metric.value)}")

    return "\n".join(lines) + "\n"


class ApplicationMetrics:
    """Process-wide singleton metrics for AutoSIEM application telemetry."""

    _instance: "ApplicationMetrics | None" = None

    def __new__(cls) -> "ApplicationMetrics":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_registry", None) is not None:
            return
        self._registry = MetricsRegistry()
        self.incidents_total = self._registry.counter("incidents_total")
        self.llm_calls_total = self._registry.counter("llm_calls_total")
        self.llm_failures_total = self._registry.counter("llm_failures_total")
        self.workload_gauge = self._registry.gauge("workload_gauge")

    def record_event(self, source: str) -> None:
        self._registry.counter("events_total", source=str(source)).inc()

    def record_finding(self, rule_id: str) -> None:
        self._registry.counter("findings_total", rule_id=str(rule_id)).inc()

    def record_incident(self) -> None:
        self.incidents_total.inc()

    def record_llm_call(self) -> None:
        self.llm_calls_total.inc()

    def record_llm_failure(self) -> None:
        self.llm_failures_total.inc()

    def render(self) -> str:
        return prometheus_text(self._registry)


@dataclass
class Span:
    """A single span within a trace."""

    span_id: str
    parent_id: str | None
    operation: str
    started_at: float
    duration_ms: float = 0.0


def _new_id() -> str:
    return uuid4().hex


class Trace:
    """A lightweight trace: a root span plus its direct child spans.

    Use :meth:`span` as a context manager; each entered block records a child
    span linked to the root via ``parent_id`` and measures its duration.
    """

    def __init__(self, operation: str = "trace") -> None:
        self.root = Span(
            span_id=_new_id(),
            parent_id=None,
            operation=operation,
            started_at=time.time(),
        )
        self.children: list[Span] = []

    @contextmanager
    def span(self, operation: str) -> Iterator[Span]:
        start = time.time()
        child = Span(
            span_id=_new_id(),
            parent_id=self.root.span_id,
            operation=operation,
            started_at=start,
        )
        self.children.append(child)
        try:
            yield child
        finally:
            child.duration_ms = (time.time() - start) * 1000.0