"""Entity behavioral analytics (UEBA).

Learns a per-entity baseline from the event stream and scores each new event
against it. Every contributing signal is named and carries its own points, so a
finding explains *why* it fired rather than emitting an opaque number.

Signals
-------
``novel_action``      the entity has never performed this action before
``novel_src_ip``      a user authenticating from a source IP never seen for them
``novel_host``        a user active on a host never seen for them
``off_hours``         activity in an hour outside the entity's learned profile
``rare_action``       an action that is rare across the whole population
``peer_rare``         an action almost no comparable entity performs
``burst``             an abnormal number of events for the entity in a short window

``peer_rare`` compares an entity against its peer group - other entities of the
same kind (``user:``, ``host:``, ``ip:``, ``cloud_account:``). "alice ran a
credential dumper and no other user ever has" is a different, stronger claim
than "alice has not run it before", which is what ``novel_action`` catches.

Statistical signals (``off_hours``, ``rare_action``, ``burst``) stay silent
until enough history exists, otherwise every entity looks anomalous on first
sight. Novelty signals need only one prior observation.

State is serializable (:meth:`BaselineState.to_dict` /
:meth:`BaselineState.from_dict`) so baselines survive across runs instead of
being relearned from zero on every invocation.

Standard library only.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from .schemas import Finding, NormalizedEvent, Severity


@runtime_checkable
class BaselineStore(Protocol):
    """Anything that can persist a UEBA baseline between runs.

    ``AutoSIEMStorage`` satisfies this. Without one the detector relearns from
    zero on every invocation, which makes every entity look novel again.
    """

    def load_baseline(self, tenant_id: str | None = ...) -> dict[str, Any] | None: ...

    def save_baseline(self, state: dict[str, Any], tenant_id: str | None = ...) -> None: ...

# --- Signal weights --------------------------------------------------------
POINTS_NOVEL_ACTION = 15
POINTS_NOVEL_SRC_IP = 25
POINTS_NOVEL_HOST = 20
POINTS_OFF_HOURS = 20
POINTS_RARE_ACTION_MAX = 20
POINTS_PEER_RARE_MAX = 20
POINTS_BURST = 25

# --- Warm-up and sensitivity ----------------------------------------------
#: Observations an entity needs before per-entity statistical signals apply.
MIN_ENTITY_OBSERVATIONS = 5
#: Events the whole population needs before global rarity applies.
MIN_GLOBAL_OBSERVATIONS = 20
#: An action seen in fewer than this fraction of all events counts as rare.
RARE_ACTION_MAX_FREQUENCY = 0.05
#: Peers of the same kind needed before peer comparison means anything.
MIN_PEER_GROUP_SIZE = 5
#: An action performed by at most this fraction of a peer group is peer-rare.
PEER_RARE_MAX_FRACTION = 0.20
#: Trailing window and count that together define a burst.
BURST_WINDOW_SECONDS = 120
BURST_THRESHOLD = 8
#: Cap on retained timestamps per entity (bounds memory on long runs).
MAX_TRACKED_TIMES = 256

#: Score at or above which an anomaly finding is emitted.
ANOMALY_FINDING_THRESHOLD = 25
#: Score at or above which the finding is HIGH rather than MEDIUM.
ANOMALY_HIGH_THRESHOLD = 50


@dataclass(slots=True)
class AnomalySignal:
    """One contributing reason an event scored as anomalous."""

    name: str
    entity: str
    points: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"signal": self.name, "entity": self.entity, "points": self.points, "detail": self.detail}


@dataclass(slots=True)
class BaselineState:
    """Learned per-entity behavioural profile.

    ``seen_actions_by_entity`` and ``seen_src_ips_by_user`` keep their original
    names and meaning so existing callers and persisted state stay valid.
    """

    seen_actions_by_entity: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    seen_src_ips_by_user: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    seen_hosts_by_user: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    hours_by_entity: dict[str, Counter[int]] = field(default_factory=lambda: defaultdict(Counter))
    observations_by_entity: Counter[str] = field(default_factory=Counter)
    action_totals: Counter[str] = field(default_factory=Counter)
    #: entity kind -> action -> number of DISTINCT entities of that kind that
    #: have ever performed it. Drives the peer_rare signal.
    peer_action_entities: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    total_events: int = 0
    recent_times_by_entity: dict[str, deque[datetime]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=MAX_TRACKED_TIMES))
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the baseline (timestamps as ISO strings) for persistence."""
        return {
            "seen_actions_by_entity": {k: dict(v) for k, v in self.seen_actions_by_entity.items()},
            "seen_src_ips_by_user": {k: dict(v) for k, v in self.seen_src_ips_by_user.items()},
            "seen_hosts_by_user": {k: dict(v) for k, v in self.seen_hosts_by_user.items()},
            "hours_by_entity": {k: {str(h): c for h, c in v.items()} for k, v in self.hours_by_entity.items()},
            "observations_by_entity": dict(self.observations_by_entity),
            "action_totals": dict(self.action_totals),
            "peer_action_entities": {k: dict(v) for k, v in self.peer_action_entities.items()},
            "total_events": self.total_events,
            "recent_times_by_entity": {
                k: [t.isoformat() for t in v] for k, v in self.recent_times_by_entity.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaselineState":
        """Rebuild a baseline from :meth:`to_dict` output. Unknown keys are ignored."""
        state = cls()
        for entity, actions in (data.get("seen_actions_by_entity") or {}).items():
            state.seen_actions_by_entity[entity] = Counter(actions)
        for user, ips in (data.get("seen_src_ips_by_user") or {}).items():
            state.seen_src_ips_by_user[user] = Counter(ips)
        for user, hosts in (data.get("seen_hosts_by_user") or {}).items():
            state.seen_hosts_by_user[user] = Counter(hosts)
        for entity, hours in (data.get("hours_by_entity") or {}).items():
            state.hours_by_entity[entity] = Counter({int(h): c for h, c in hours.items()})
        state.observations_by_entity = Counter(data.get("observations_by_entity") or {})
        state.action_totals = Counter(data.get("action_totals") or {})
        for kind, actions in (data.get("peer_action_entities") or {}).items():
            state.peer_action_entities[kind] = Counter(actions)
        state.total_events = int(data.get("total_events") or 0)
        for entity, times in (data.get("recent_times_by_entity") or {}).items():
            state.recent_times_by_entity[entity] = deque(
                (datetime.fromisoformat(t) for t in times), maxlen=MAX_TRACKED_TIMES
            )
        return state

    def peer_group_size(self, kind: str) -> int:
        """How many distinct entities of ``kind`` the baseline has observed."""
        prefix = f"{kind}:"
        return sum(1 for entity in self.observations_by_entity if entity.startswith(prefix))


def entity_kind(entity: str) -> str:
    """``user:alice`` -> ``user``. Entities without a prefix map to themselves."""
    kind, separator, _ = entity.partition(":")
    return kind if separator else entity


class AnomalyDetector:
    """Scores events against a learned :class:`BaselineState`."""

    def __init__(self, state: BaselineState | None = None) -> None:
        self.state = state or BaselineState()

    # -- scoring -----------------------------------------------------------
    def signals(self, event: NormalizedEvent) -> list[AnomalySignal]:
        """Every signal this event trips, without mutating the baseline."""
        found: list[AnomalySignal] = []
        found.extend(self._novelty_signals(event))
        found.extend(self._temporal_signals(event))
        found.extend(self._peer_signals(event))
        rare = self._rare_action_signal(event)
        if rare:
            found.append(rare)
        return found

    def _peer_signals(self, event: NormalizedEvent) -> list[AnomalySignal]:
        """Flag actions that almost nobody comparable performs.

        The entity itself is excluded from the peer count, so "alice did X and
        no other user ever has" scores even after alice has done X before.
        """
        found: list[AnomalySignal] = []
        for entity in event.entity_keys():
            kind = entity_kind(entity)
            peers = self.state.peer_group_size(kind)
            if peers < MIN_PEER_GROUP_SIZE:
                continue
            doers = self.state.peer_action_entities.get(kind, Counter()).get(event.action, 0)
            already_did_it = self.state.seen_actions_by_entity.get(entity, Counter()).get(event.action, 0) > 0
            other_doers = doers - 1 if already_did_it else doers
            other_peers = peers - 1
            if other_peers <= 0:
                continue
            fraction = other_doers / other_peers
            if fraction > PEER_RARE_MAX_FRACTION:
                continue
            scale = 1.0 - (fraction / PEER_RARE_MAX_FRACTION)
            points = max(1, round(POINTS_PEER_RARE_MAX * scale))
            found.append(
                AnomalySignal(
                    "peer_rare",
                    entity,
                    points,
                    f"'{event.action}' performed by {other_doers} of {other_peers} other "
                    f"{kind} peer(s) ({fraction:.0%} of the peer group)",
                )
            )
        return found

    def _novelty_signals(self, event: NormalizedEvent) -> list[AnomalySignal]:
        found: list[AnomalySignal] = []
        for entity in event.entity_keys():
            actions = self.state.seen_actions_by_entity.get(entity)
            if actions and event.action not in actions:
                found.append(
                    AnomalySignal(
                        "novel_action",
                        entity,
                        POINTS_NOVEL_ACTION,
                        f"{entity} has never performed '{event.action}' "
                        f"({len(actions)} action(s) previously seen)",
                    )
                )
        if event.user and event.src_ip:
            seen_ips = self.state.seen_src_ips_by_user.get(event.user)
            if seen_ips and event.src_ip not in seen_ips:
                found.append(
                    AnomalySignal(
                        "novel_src_ip",
                        f"user:{event.user}",
                        POINTS_NOVEL_SRC_IP,
                        f"first activity for {event.user} from {event.src_ip} "
                        f"({len(seen_ips)} source IP(s) previously seen)",
                    )
                )
        if event.user and event.host:
            seen_hosts = self.state.seen_hosts_by_user.get(event.user)
            if seen_hosts and event.host not in seen_hosts:
                found.append(
                    AnomalySignal(
                        "novel_host",
                        f"user:{event.user}",
                        POINTS_NOVEL_HOST,
                        f"first activity for {event.user} on host {event.host} "
                        f"({len(seen_hosts)} host(s) previously seen)",
                    )
                )
        return found

    def _temporal_signals(self, event: NormalizedEvent) -> list[AnomalySignal]:
        """Off-hours and burst signals, both gated on entity warm-up."""
        found: list[AnomalySignal] = []
        for entity in event.entity_keys():
            if self.state.observations_by_entity.get(entity, 0) < MIN_ENTITY_OBSERVATIONS:
                continue
            hours = self.state.hours_by_entity.get(entity)
            if hours and event.timestamp.hour not in hours:
                active = ", ".join(f"{h:02d}:00" for h in sorted(hours))
                found.append(
                    AnomalySignal(
                        "off_hours",
                        entity,
                        POINTS_OFF_HOURS,
                        f"{entity} active at {event.timestamp.hour:02d}:00, "
                        f"outside its learned hours ({active})",
                    )
                )
            recent = self.state.recent_times_by_entity.get(entity)
            if recent:
                window_start = event.timestamp - timedelta(seconds=BURST_WINDOW_SECONDS)
                in_window = sum(1 for t in recent if t >= window_start) + 1
                if in_window >= BURST_THRESHOLD:
                    found.append(
                        AnomalySignal(
                            "burst",
                            entity,
                            POINTS_BURST,
                            f"{in_window} events for {entity} within "
                            f"{BURST_WINDOW_SECONDS}s (threshold {BURST_THRESHOLD})",
                        )
                    )
        return found

    def _rare_action_signal(self, event: NormalizedEvent) -> AnomalySignal | None:
        """Population-wide rarity, scaled so the rarest actions score highest."""
        if self.state.total_events < MIN_GLOBAL_OBSERVATIONS:
            return None
        seen = self.state.action_totals.get(event.action, 0)
        if seen == 0:
            frequency = 0.0
        else:
            frequency = seen / self.state.total_events
        if frequency > RARE_ACTION_MAX_FREQUENCY:
            return None
        scale = 1.0 - (frequency / RARE_ACTION_MAX_FREQUENCY)
        points = max(1, round(POINTS_RARE_ACTION_MAX * scale))
        entity = event.entity_keys()[0] if event.entity_keys() else "global:unknown"
        return AnomalySignal(
            "rare_action",
            entity,
            points,
            f"action '{event.action}' seen {seen} time(s) in "
            f"{self.state.total_events} events ({frequency:.1%} of traffic)",
        )

    def score(self, event: NormalizedEvent) -> int:
        """Total anomaly score for ``event``, capped at 100. Does not mutate state."""
        return min(sum(signal.points for signal in self.signals(event)), 100)

    # -- learning ----------------------------------------------------------
    def update(self, event: NormalizedEvent) -> None:
        """Fold ``event`` into the baseline."""
        for entity in event.entity_keys():
            # Count this entity toward its peer group for this action only the
            # first time it performs it, so peer_action_entities stays a count
            # of distinct entities rather than of events.
            if self.state.seen_actions_by_entity[entity][event.action] == 0:
                self.state.peer_action_entities[entity_kind(entity)][event.action] += 1
            self.state.seen_actions_by_entity[entity][event.action] += 1
            self.state.hours_by_entity[entity][event.timestamp.hour] += 1
            self.state.observations_by_entity[entity] += 1
            self.state.recent_times_by_entity[entity].append(event.timestamp)
        if event.user and event.src_ip:
            self.state.seen_src_ips_by_user[event.user][event.src_ip] += 1
        if event.user and event.host:
            self.state.seen_hosts_by_user[event.user][event.host] += 1
        self.state.action_totals[event.action] += 1
        self.state.total_events += 1

    # -- finding -----------------------------------------------------------
    def finding_for_event(self, event: NormalizedEvent) -> Finding | None:
        """Score, learn, and emit a finding when the score clears the threshold."""
        signals = self.signals(event)
        score = min(sum(signal.points for signal in signals), 100)
        self.update(event)
        if score < ANOMALY_FINDING_THRESHOLD:
            return None
        severity = Severity.HIGH if score >= ANOMALY_HIGH_THRESHOLD else Severity.MEDIUM
        names = ", ".join(sorted({signal.name for signal in signals}))
        return Finding(
            finding_id=f"anomaly-{event.event_id}",
            rule_id="builtin-anomaly-baseline",
            rule_name=f"Behavioral anomaly ({names})",
            event_id=event.event_id,
            timestamp=event.timestamp,
            severity=severity,
            risk_points=score,
            entities=event.entity_keys(),
            mitre_attack=[],
            evidence={
                "event": event.to_dict(),
                "anomaly_score": score,
                "signals": [signal.to_dict() for signal in signals],
            },
        )
