from __future__ import annotations

import pytest

from autosiem.metrics import (
    ApplicationMetrics,
    Counter,
    Gauge,
    Histogram,
    MetricsRegistry,
    Trace,
    prometheus_text,
)


def test_counter_and_gauge() -> None:
    c = Counter("events")
    c.inc()
    c.inc(2)
    assert c.value == 3

    g = Gauge("jobs")
    g.set(5)
    g.inc(2)
    g.dec(1)
    assert g.value == 6


def test_histogram_cumulative() -> None:
    h = Histogram("latency", buckets=(0.1, 0.5, 1.0))
    for value in (0.05, 0.2, 0.9, 2.0):
        h.observe(value)

    assert h.count == 4
    assert h.sum == pytest.approx(0.05 + 0.2 + 0.9 + 2.0)
    # Cumulative: le=0.1 -> 1 (0.05); le=0.5 -> 2 (+0.2); le=1.0 -> 3 (+0.9).
    assert h.bucket_counts() == [1, 2, 3]


def test_registry_create_or_return() -> None:
    reg = MetricsRegistry()
    c1 = reg.counter("reqs", method="GET")
    c2 = reg.counter("reqs", method="GET")
    c3 = reg.counter("reqs", method="POST")
    assert c1 is c2
    assert c1 is not c3

    g1 = reg.gauge("load")
    g2 = reg.gauge("load")
    assert g1 is g2

    h1 = reg.histogram("dur")
    h2 = reg.histogram("dur")
    assert h1 is h2


def test_prometheus_text_content() -> None:
    reg = MetricsRegistry()
    c = reg.counter("http_requests", method="GET")
    c.inc()
    h = reg.histogram("request_duration")
    h.observe(0.05)
    h.observe(0.4)

    out = prometheus_text(reg)
    assert 'http_requests{method="GET"} 1' in out
    assert 'request_duration_bucket{le="0.05"} 1' in out
    assert 'request_duration_bucket{le="0.5"} 2' in out
    assert 'request_duration_bucket{le="+Inf"} 2' in out
    assert "request_duration_sum" in out
    assert "request_duration_count 2" in out

    # Two renders are byte-identical (deterministic).
    assert out == prometheus_text(reg)


def test_application_metrics_render_deterministic() -> None:
    am = ApplicationMetrics()
    am.record_event("syslog")
    am.record_event("syslog")
    am.record_event("file")
    am.record_finding("rule-x")
    am.record_incident()
    am.record_llm_call()
    am.record_llm_failure()
    am.workload_gauge.set(4)

    out1 = am.render()
    out2 = am.render()
    assert out1 == out2

    assert 'events_total{source="syslog"}' in out1
    assert 'events_total{source="file"}' in out1
    assert 'findings_total{rule_id="rule-x"}' in out1
    assert "incidents_total" in out1
    assert "llm_calls_total" in out1
    assert "llm_failures_total" in out1
    assert "workload_gauge" in out1


def test_trace_parent_child() -> None:
    trace = Trace("request")
    with trace.span("auth"):
        pass
    with trace.span("enrich"):
        with trace.span("lookup"):
            pass

    assert trace.root.parent_id is None
    assert [s.operation for s in trace.children] == ["auth", "enrich", "lookup"]
    assert len(trace.children) == 3
    assert all(s.parent_id == trace.root.span_id for s in trace.children)
    assert all(s.duration_ms >= 0 for s in trace.children)