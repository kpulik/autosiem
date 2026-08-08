"""Tests for the entity behavioral analytics (UEBA) engine.

Each signal is tested in isolation: build a baseline with `update()`, then
score a probe event that should trip exactly one signal.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from autosiem.anomaly import (
    ANOMALY_FINDING_THRESHOLD,
    BURST_THRESHOLD,
    MIN_ENTITY_OBSERVATIONS,
    MIN_GLOBAL_OBSERVATIONS,
    MIN_PEER_GROUP_SIZE,
    POINTS_NOVEL_ACTION,
    POINTS_NOVEL_HOST,
    POINTS_NOVEL_SRC_IP,
    POINTS_OFF_HOURS,
    POINTS_PEER_RARE_MAX,
    AnomalyDetector,
    BaselineState,
    entity_kind,
)
from autosiem.schemas import NormalizedEvent, Severity

BASE_TIME = datetime(2026, 8, 4, 10, 0, 0, tzinfo=timezone.utc)


def _event(
    action: str = "login_success",
    user: str | None = "alice",
    host: str | None = "workstation-7",
    src_ip: str | None = "203.0.113.10",
    offset_seconds: int = 0,
    hour: int | None = None,
    category: str = "authentication",
) -> NormalizedEvent:
    timestamp = BASE_TIME + timedelta(seconds=offset_seconds)
    if hour is not None:
        timestamp = timestamp.replace(hour=hour)
    return NormalizedEvent(
        timestamp=timestamp,
        category=category,  # type: ignore[arg-type]
        action=action,
        user=user,
        host=host,
        src_ip=src_ip,
    )


def _signal_names(detector: AnomalyDetector, event: NormalizedEvent) -> set[str]:
    return {signal.name for signal in detector.signals(event)}


# --- cold start ------------------------------------------------------------


def test_first_event_for_entity_is_not_anomalous() -> None:
    """Nothing is known yet, so nothing can deviate from a baseline."""
    detector = AnomalyDetector()
    assert detector.score(_event()) == 0
    assert detector.finding_for_event(_event()) is None


# --- novelty signals -------------------------------------------------------


def test_novel_action_scores_once_per_entity() -> None:
    detector = AnomalyDetector()
    detector.update(_event(action="login_success"))
    # Same user/host/ip, brand-new action: user, host and ip entities each fire.
    signals = detector.signals(_event(action="file_delete"))
    novel = [s for s in signals if s.name == "novel_action"]
    assert {s.entity for s in novel} == {"user:alice", "host:workstation-7", "ip:203.0.113.10"}
    assert all(s.points == POINTS_NOVEL_ACTION for s in novel)


def test_novel_src_ip_for_known_user() -> None:
    detector = AnomalyDetector()
    detector.update(_event(src_ip="203.0.113.10"))
    signals = {s.name: s for s in detector.signals(_event(src_ip="198.51.100.25"))}
    assert "novel_src_ip" in signals
    assert signals["novel_src_ip"].points == POINTS_NOVEL_SRC_IP
    assert "198.51.100.25" in signals["novel_src_ip"].detail


def test_novel_host_for_known_user() -> None:
    detector = AnomalyDetector()
    detector.update(_event(host="workstation-7"))
    signals = {s.name: s for s in detector.signals(_event(host="finance-02"))}
    assert "novel_host" in signals
    assert signals["novel_host"].points == POINTS_NOVEL_HOST
    assert "finance-02" in signals["novel_host"].detail


def test_repeating_known_behaviour_stays_silent() -> None:
    """Identical behaviour at a normal cadence is the definition of baseline.

    Events are spaced 5 minutes apart: same hour (so ``off_hours`` stays quiet)
    and wider than the 120s burst window (so ``burst`` stays quiet).
    """
    detector = AnomalyDetector()
    for index in range(10):
        detector.update(_event(offset_seconds=index * 300))
    assert detector.score(_event(offset_seconds=10 * 300)) == 0


# --- temporal signals ------------------------------------------------------


def test_off_hours_requires_warmup() -> None:
    """Below the warm-up threshold an unusual hour must not fire."""
    detector = AnomalyDetector()
    for index in range(MIN_ENTITY_OBSERVATIONS - 1):
        detector.update(_event(offset_seconds=index * 3600, hour=10))
    assert "off_hours" not in _signal_names(detector, _event(hour=3))


def test_off_hours_fires_after_warmup() -> None:
    detector = AnomalyDetector()
    for index in range(MIN_ENTITY_OBSERVATIONS + 2):
        detector.update(_event(offset_seconds=index * 3600, hour=10))
    signals = {s.name: s for s in detector.signals(_event(hour=3))}
    assert "off_hours" in signals
    assert signals["off_hours"].points == POINTS_OFF_HOURS
    assert "03:00" in signals["off_hours"].detail


def test_burst_fires_on_rapid_repeat() -> None:
    """Many events for one entity inside the burst window trip the signal."""
    detector = AnomalyDetector()
    for index in range(BURST_THRESHOLD):
        detector.update(_event(offset_seconds=index))
    assert "burst" in _signal_names(detector, _event(offset_seconds=BURST_THRESHOLD))


def test_burst_ignores_events_outside_the_window() -> None:
    detector = AnomalyDetector()
    for index in range(BURST_THRESHOLD + 2):
        # One hour apart: never more than one event inside a 120s window.
        detector.update(_event(offset_seconds=index * 3600))
    probe = _event(offset_seconds=(BURST_THRESHOLD + 2) * 3600)
    assert "burst" not in _signal_names(detector, probe)


# --- population rarity -----------------------------------------------------


def test_rare_action_requires_global_warmup() -> None:
    detector = AnomalyDetector()
    detector.update(_event(action="login_success"))
    assert "rare_action" not in _signal_names(detector, _event(action="mimikatz"))


def test_rare_action_fires_once_population_is_large_enough() -> None:
    detector = AnomalyDetector()
    for index in range(MIN_GLOBAL_OBSERVATIONS + 5):
        detector.update(_event(action="login_success", user=f"user{index}", host=None, src_ip=None))
    signals = {s.name: s for s in detector.signals(_event(action="mimikatz", user="zed", host=None, src_ip=None))}
    assert "rare_action" in signals
    assert signals["rare_action"].points > 0


def test_common_action_is_not_rare() -> None:
    detector = AnomalyDetector()
    for index in range(MIN_GLOBAL_OBSERVATIONS + 5):
        detector.update(_event(action="login_success", user=f"user{index}", host=None, src_ip=None))
    probe = _event(action="login_success", user="zed", host=None, src_ip=None)
    assert "rare_action" not in _signal_names(detector, probe)


# --- peer group ------------------------------------------------------------


def _populate_peers(detector: AnomalyDetector, names: list[str], actions: list[str]) -> None:
    """Give each named user a history of the given routine actions."""
    for index, name in enumerate(names):
        for action in actions:
            detector.update(_event(action=action, user=name, host=None, src_ip=None, offset_seconds=index * 600))


PEERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]


def test_peer_rare_requires_a_peer_group() -> None:
    """Below the minimum group size, peer comparison means nothing."""
    detector = AnomalyDetector()
    _populate_peers(detector, PEERS[: MIN_PEER_GROUP_SIZE - 1], ["login_success"])
    probe = _event(action="mimikatz", user="alice", host=None, src_ip=None, offset_seconds=9999)
    assert "peer_rare" not in _signal_names(detector, probe)


def test_peer_rare_fires_when_no_peer_does_it() -> None:
    detector = AnomalyDetector()
    _populate_peers(detector, PEERS, ["login_success", "open_file"])
    probe = _event(action="mimikatz", user="alice", host=None, src_ip=None, offset_seconds=9999)

    signals = {signal.name: signal for signal in detector.signals(probe)}
    assert "peer_rare" in signals
    assert signals["peer_rare"].points == POINTS_PEER_RARE_MAX
    assert "0 of 7 other user peer(s)" in signals["peer_rare"].detail


def test_widely_shared_action_is_not_peer_rare() -> None:
    detector = AnomalyDetector()
    _populate_peers(detector, PEERS, ["login_success"])
    probe = _event(action="login_success", user="alice", host=None, src_ip=None, offset_seconds=9999)
    assert "peer_rare" not in _signal_names(detector, probe)


def test_peer_rare_stops_firing_once_peers_adopt_the_action() -> None:
    detector = AnomalyDetector()
    _populate_peers(detector, PEERS, ["login_success"])
    probe = _event(action="admin_tool", user="alice", host=None, src_ip=None, offset_seconds=9999)
    assert "peer_rare" in _signal_names(detector, probe)

    for index, name in enumerate(PEERS[1:]):
        detector.update(_event(action="admin_tool", user=name, host=None, src_ip=None, offset_seconds=9000 + index))
    assert "peer_rare" not in _signal_names(detector, probe)


def test_peer_rare_excludes_the_entity_itself() -> None:
    """alice repeating a peer-unique action is still peer-rare, not normalised."""
    detector = AnomalyDetector()
    _populate_peers(detector, PEERS, ["login_success"])
    probe = _event(action="admin_tool", user="alice", host=None, src_ip=None, offset_seconds=9999)
    detector.update(probe)  # alice has now done it once

    signals = {signal.name: signal for signal in detector.signals(probe)}
    assert "novel_action" not in signals  # she has done it before
    assert "peer_rare" in signals  # but no peer has
    assert "0 of 7 other user peer(s)" in signals["peer_rare"].detail


def test_peer_counts_track_distinct_entities_not_events() -> None:
    detector = AnomalyDetector()
    for index in range(10):
        detector.update(_event(action="login_success", user="alice", host=None, src_ip=None, offset_seconds=index * 600))
    assert detector.state.peer_action_entities["user"]["login_success"] == 1


def test_peer_groups_are_scoped_by_entity_kind() -> None:
    detector = AnomalyDetector()
    _populate_peers(detector, PEERS, ["login_success"])
    assert detector.state.peer_group_size("user") == len(PEERS)
    assert detector.state.peer_group_size("host") == 0


def test_entity_kind_parsing() -> None:
    assert entity_kind("user:alice") == "user"
    assert entity_kind("cloud_account:prod") == "cloud_account"
    assert entity_kind("global:unknown") == "global"
    assert entity_kind("bare") == "bare"


# --- findings --------------------------------------------------------------


def test_finding_carries_signal_breakdown() -> None:
    detector = AnomalyDetector()
    detector.update(_event())
    finding = detector.finding_for_event(_event(action="file_delete", src_ip="198.51.100.25", host="finance-02"))
    assert finding is not None
    assert finding.rule_id == "builtin-anomaly-baseline"
    assert finding.risk_points >= ANOMALY_FINDING_THRESHOLD
    names = {entry["signal"] for entry in finding.evidence["signals"]}
    assert {"novel_action", "novel_src_ip", "novel_host"} <= names
    # Every signal explains itself.
    assert all(entry["detail"] for entry in finding.evidence["signals"])
    assert finding.evidence["anomaly_score"] == finding.risk_points


def test_score_is_capped_at_100() -> None:
    detector = AnomalyDetector()
    for index in range(MIN_ENTITY_OBSERVATIONS + 2):
        detector.update(_event(offset_seconds=index, hour=10))
    # Novel action + novel ip + novel host + off-hours + burst across 3 entities.
    probe = _event(action="exfiltrate", src_ip="10.0.0.9", host="dc-01", hour=3, offset_seconds=10)
    assert detector.score(probe) == 100


def test_high_severity_above_threshold() -> None:
    detector = AnomalyDetector()
    detector.update(_event())
    finding = detector.finding_for_event(_event(action="file_delete", src_ip="198.51.100.25", host="finance-02"))
    assert finding is not None
    assert finding.severity is Severity.HIGH


def test_finding_for_event_learns_from_the_event() -> None:
    """The same deviation must not fire twice — it becomes the new normal."""
    detector = AnomalyDetector()
    detector.update(_event())
    probe = _event(action="file_delete", src_ip="198.51.100.25", host="finance-02")
    assert detector.finding_for_event(probe) is not None
    assert detector.finding_for_event(probe) is None


# --- persistence -----------------------------------------------------------


def test_baseline_round_trips_through_dict() -> None:
    detector = AnomalyDetector()
    for index in range(MIN_ENTITY_OBSERVATIONS + 2):
        detector.update(_event(offset_seconds=index * 60))

    restored = AnomalyDetector(BaselineState.from_dict(detector.state.to_dict()))

    assert restored.state.total_events == detector.state.total_events
    assert restored.state.action_totals == detector.state.action_totals
    assert restored.state.seen_hosts_by_user == detector.state.seen_hosts_by_user
    assert restored.state.hours_by_entity == detector.state.hours_by_entity
    assert restored.state.peer_action_entities == detector.state.peer_action_entities
    # A restored baseline scores identically to the one it was copied from.
    probe = _event(action="file_delete", src_ip="198.51.100.25")
    assert restored.score(probe) == detector.score(probe)


def test_restored_baseline_suppresses_known_behaviour() -> None:
    """Persistence is the point: known behaviour stays known across a restart."""
    detector = AnomalyDetector()
    for index in range(MIN_ENTITY_OBSERVATIONS):
        detector.update(_event(offset_seconds=index * 3600))
    snapshot = detector.state.to_dict()

    cold = AnomalyDetector()
    warm = AnomalyDetector(BaselineState.from_dict(snapshot))
    probe = _event(action="login_success", offset_seconds=99999)

    assert cold.score(probe) == 0  # cold start knows nothing, so nothing deviates
    assert warm.score(probe) == 0  # warm start recognises it as normal
    # But the warm baseline still flags something genuinely new.
    assert warm.score(_event(action="mimikatz", offset_seconds=99999)) > 0


def test_from_dict_ignores_unknown_keys() -> None:
    state = BaselineState.from_dict({"total_events": 3, "not_a_real_field": [1, 2, 3]})
    assert state.total_events == 3


@pytest.mark.parametrize("payload", [{}, {"seen_actions_by_entity": {}}])
def test_from_dict_handles_empty_payloads(payload: dict) -> None:
    state = BaselineState.from_dict(payload)
    assert state.total_events == 0
    assert AnomalyDetector(state).score(_event()) == 0
