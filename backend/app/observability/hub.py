"""The telemetry hub: bounded in-memory buffers, de-duplication, incremental reads and live fan-out.

Every buffer has a hard cap: series count, points per series, events, flows and each subscriber's queue. When a cap is
reached the oldest data goes first and the drop is counted, so a burst of ingestion can never grow memory without
limit or stall the API. Readers ask for data after a sequence cursor, so clients poll or stream incrementally.
"""
import asyncio
import logging
import math
import threading
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.observability.adapters import FlowRecord, NetworkEventRecord, TelemetrySample

log = logging.getLogger(__name__)
INGEST = "ingest"


def sim_namespace(scenario_id: str) -> str:
    return f"sim:{scenario_id}"


@dataclass(eq=False)  # identity semantics: each live stream is its own subscriber in the hub's set
class Subscriber:
    loop: asyncio.AbstractEventLoop
    namespaces: frozenset[str]
    queue: asyncio.Queue
    owner: str = ""
    dropped: int = 0


@dataclass
class Series:
    namespace: str
    device_id: str
    interface: str | None
    metric: str
    source: str
    points: deque = field(default_factory=deque)  # (sequence, epoch seconds, value)


class TelemetryHub:
    def __init__(self, max_series: int = 2000, points_per_series: int = 720, max_events: int = 5000,
                 max_flows: int = 20000, subscriber_queue: int = 256, max_subscribers: int = 64) -> None:
        self.max_series, self.points_per_series = max_series, points_per_series
        self.subscriber_queue, self.max_subscribers = subscriber_queue, max_subscribers
        self.lock = threading.Lock()
        self.series: OrderedDict[str, Series] = OrderedDict()
        self.events: deque[tuple[int, str, NetworkEventRecord]] = deque(maxlen=max_events)
        self.flows: deque[tuple[int, str, FlowRecord]] = deque(maxlen=max_flows)
        self.sequence = 0
        self.stats: Counter[str] = Counter()
        self.subscribers: set[Subscriber] = set()
        self.started_at = datetime.now(timezone.utc)

    # ------------------------------------------------------------ writes

    def ingest_samples(self, samples: list[TelemetrySample], namespace: str = INGEST) -> dict[str, int]:
        accepted, duplicates, published = 0, 0, []
        with self.lock:
            for sample in samples:
                key = f"{namespace}|{sample.key}"
                series = self.series.get(key)
                if series is None:
                    if len(self.series) >= self.max_series:
                        self.series.popitem(last=False)
                        self.stats["series_evicted"] += 1
                    series = self.series[key] = Series(namespace, sample.device_id, sample.interface, sample.metric, sample.source,
                                                       deque(maxlen=self.points_per_series))
                else:
                    self.series.move_to_end(key)
                moment = sample.timestamp.timestamp()
                if series.points and moment <= series.points[-1][1]:
                    duplicates += 1
                    continue
                if len(series.points) == series.points.maxlen:
                    self.stats["points_expired"] += 1
                self.sequence += 1
                series.points.append((self.sequence, moment, sample.value))
                accepted += 1
                published.append({"s": self.sequence, "d": sample.device_id, "i": sample.interface, "m": sample.metric,
                                  "t": sample.timestamp.isoformat(), "v": round(sample.value, 4)})
            self.stats["samples_accepted"] += accepted
            self.stats["samples_duplicate"] += duplicates
        if published:
            self.publish(namespace, {"type": "metrics", "namespace": namespace, "samples": published})
        return {"accepted": accepted, "duplicates": duplicates}

    def ingest_events(self, events: list[NetworkEventRecord], namespace: str = INGEST) -> int:
        with self.lock:
            entries = []
            for event in events:
                self.sequence += 1
                if len(self.events) == self.events.maxlen:
                    self.stats["events_expired"] += 1
                self.events.append((self.sequence, namespace, event))
                entries.append((self.sequence, event))
            self.stats["events_accepted"] += len(entries)
        for sequence, event in entries:
            self.publish(namespace, {"type": "event", "namespace": namespace, "sequence": sequence,
                                     "event": event.model_dump(mode="json")})
        return len(entries)

    def ingest_flows(self, flows: list[FlowRecord], namespace: str = INGEST) -> int:
        with self.lock:
            for flow in flows:
                self.sequence += 1
                if len(self.flows) == self.flows.maxlen:
                    self.stats["flows_expired"] += 1
                self.flows.append((self.sequence, namespace, flow))
            self.stats["flows_accepted"] += len(flows)
            sequence = self.sequence
        if flows:
            self.publish(namespace, {"type": "flows", "namespace": namespace, "sequence": sequence, "count": len(flows),
                                     "bytes": sum(f.bytes for f in flows)})
        return len(flows)

    def count(self, name: str, amount: int = 1) -> None:
        with self.lock:
            self.stats[name] += amount

    # ------------------------------------------------------------ reads

    def read_series(self, namespaces: set[str], since: int = 0, device_id: str | None = None, interface: str | None = None,
                    metric: str | None = None, max_points: int = 5000) -> dict[str, Any]:
        result, cursor, truncated, total = [], since, False, 0
        with self.lock:
            for series in self.series.values():
                if series.namespace not in namespaces or (device_id and series.device_id != device_id) \
                        or (interface and series.interface != interface) or (metric and series.metric != metric):
                    continue
                fresh = [p for p in series.points if p[0] > since]
                if not fresh:
                    continue
                room = max_points - total
                if room <= 0:
                    truncated = True
                    break
                if len(fresh) > room:
                    fresh, truncated = fresh[-room:], True
                total += len(fresh)
                cursor = max(cursor, fresh[-1][0])
                result.append({"device_id": series.device_id, "interface": series.interface, "metric": series.metric,
                               "source": series.source, "namespace": series.namespace,
                               "points": [[datetime.fromtimestamp(t, timezone.utc).isoformat(), None if math.isnan(v) else v]
                                          for _, t, v in fresh]})
            latest = self.sequence
        return {"cursor": latest if not truncated else cursor, "series": result, "points": total, "truncated": truncated}

    def latest_values(self, namespaces: set[str]) -> dict[tuple[str, str | None, str], tuple[float, float]]:
        with self.lock:
            return {(s.device_id, s.interface, s.metric): (s.points[-1][1], s.points[-1][2])
                    for s in self.series.values() if s.namespace in namespaces and s.points}

    def read_events(self, namespaces: set[str], since: int = 0, limit: int = 200) -> list[tuple[int, NetworkEventRecord]]:
        with self.lock:
            return [(seq, event) for seq, ns, event in self.events if ns in namespaces and seq > since][-limit:]

    def read_flows(self, namespaces: set[str], since: int = 0, limit: int = 5000) -> list[tuple[int, FlowRecord]]:
        with self.lock:
            return [(seq, flow) for seq, ns, flow in self.flows if ns in namespaces and seq > since][-limit:]

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            namespaces = Counter(s.namespace for s in self.series.values())
            return {
                "started_at": self.started_at.isoformat(), "sequence": self.sequence, "series": len(self.series),
                "series_by_namespace": dict(namespaces), "events_buffered": len(self.events), "flows_buffered": len(self.flows),
                "subscribers": len(self.subscribers), "stats": dict(self.stats),
                "limits": {"max_series": self.max_series, "points_per_series": self.points_per_series,
                           "max_events": self.events.maxlen, "max_flows": self.flows.maxlen,
                           "subscriber_queue": self.subscriber_queue, "max_subscribers": self.max_subscribers},
            }

    # ------------------------------------------------------------ live fan-out

    def subscribe(self, namespaces: set[str], owner: str = "", per_owner: int | None = None) -> Subscriber | None:
        """Registers a live stream, atomically enforcing the global and per-owner caps; None when either is reached."""
        with self.lock:
            owned = sum(s.owner == owner for s in self.subscribers)
            if len(self.subscribers) >= self.max_subscribers or (per_owner is not None and owned >= per_owner):
                self.stats["subscribers_refused"] += 1
                return None
            subscriber = Subscriber(asyncio.get_running_loop(), frozenset(namespaces), asyncio.Queue(self.subscriber_queue), owner)
            self.subscribers.add(subscriber)
            return subscriber

    def streams_of(self, owner: str) -> int:
        with self.lock:
            return sum(s.owner == owner for s in self.subscribers)

    def unsubscribe(self, subscriber: Subscriber) -> None:
        with self.lock:
            self.subscribers.discard(subscriber)
            self.stats["subscriber_messages_dropped"] += subscriber.dropped

    def publish(self, namespace: str, message: dict[str, Any]) -> None:
        with self.lock:
            targets = [s for s in self.subscribers if namespace in s.namespaces]
        for subscriber in targets:
            try:
                subscriber.loop.call_soon_threadsafe(self.offer, subscriber, message)
            except RuntimeError:
                pass  # the subscriber's loop has closed; it unsubscribes on its way out

    @staticmethod
    def offer(subscriber: Subscriber, message: dict[str, Any]) -> None:
        """Drop-oldest: a slow client loses old updates rather than holding memory or blocking producers."""
        if subscriber.queue.full():
            try:
                subscriber.queue.get_nowait()
                subscriber.dropped += 1
            except asyncio.QueueEmpty:
                pass
        subscriber.queue.put_nowait(message)

    def active_namespaces(self) -> set[str]:
        with self.lock:
            return {ns for s in self.subscribers for ns in s.namespaces}
