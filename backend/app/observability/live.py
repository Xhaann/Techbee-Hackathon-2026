"""The live simulator: wall-clock telemetry for scenarios someone is watching, continuing each scenario's end state.

It only produces samples for scenarios with an active subscriber or a recent request (at most `max_scenarios`), so an
idle server does no work. Values are labelled `simulator` everywhere they surface.
"""
import asyncio
import logging
import math
import time
from datetime import datetime, timezone

from app.network.repository import load_scenario, load_topology
from app.observability.adapters import TelemetrySample
from app.observability.hub import TelemetryHub, sim_namespace
from app.observability.simulation import (
    DOWN,
    SITE_GEO,
    UNKNOWN,
    business_shape,
    interface_history,
    monitored_interfaces,
    profile_for,
    seeded,
)

log = logging.getLogger(__name__)
ACTIVE_SECONDS = 600


def live_samples(scenario_id: str, moment: datetime, step_seconds: float = 5.0) -> list[TelemetrySample]:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    slot = int(moment.timestamp() // max(step_seconds, 0.1))
    samples = []
    for interface_id in monitored_interfaces(dataset):
        history = interface_history(scenario_id, interface_id)
        last = len(history) - 1
        state = history.status[last]
        if state == UNKNOWN:
            continue  # the scenario's telemetry gap continues: nothing is reported
        device_id, name = interface_id.split(":", 1)
        profile, link_id = profile_for(topology, interface_id)
        rng = seeded("live", scenario_id, link_id or interface_id, slot)
        offset = SITE_GEO[history.site_id].utc_offset_hours
        base = []
        if state == DOWN:
            base = [("oper_status", 0.0), ("utilization_percent", 0.0), ("packet_loss_percent", 100.0)]
        else:
            # The scenario's last level, moved by the difference in business-hours shape between now and then.
            swing = (business_shape(moment, offset) - business_shape(history.at(last), offset)) * 12
            utilization = min(99.0, max(0.1, history.utilization[last] + swing + rng.gauss(0, profile.noise * 0.6)))
            loss = history.loss[last]
            base = [("oper_status", 1.0), ("utilization_percent", utilization),
                    ("packet_loss_percent", max(0.0, (0.0 if math.isnan(loss) else loss) + rng.gauss(0, 0.02)))]
            latency = history.latency[last]
            if not math.isnan(latency):
                base.append(("latency_ms", max(0.1, latency * (1 + rng.gauss(0, 0.02)))))
        samples += [TelemetrySample(device_id=device_id, interface=name, metric=metric, value=round(value, 3), timestamp=moment,
                                    source="simulator") for metric, value in base]
    return samples


class LiveSimulator:
    def __init__(self, hub: TelemetryHub, interval_seconds: float = 5.0, max_scenarios: int = 4) -> None:
        self.hub = hub
        self.interval = interval_seconds
        self.max_scenarios = max_scenarios
        self.requested: dict[str, float] = {}
        self.task: asyncio.Task | None = None
        self.ticks = 0

    def touch(self, scenario_id: str) -> None:
        self.requested[scenario_id] = time.monotonic()
        if len(self.requested) > self.max_scenarios:
            oldest = min(self.requested, key=self.requested.get)
            self.requested.pop(oldest, None)

    def active(self) -> list[str]:
        now = time.monotonic()
        watched = {ns.split(":", 1)[1] for ns in self.hub.active_namespaces() if ns.startswith("sim:")}
        recent = {s for s, at in self.requested.items() if now - at <= ACTIVE_SECONDS}
        return sorted(watched | recent)[: self.max_scenarios]

    def tick(self, scenario_id: str, moment: datetime | None = None) -> int:
        samples = live_samples(scenario_id, moment or datetime.now(timezone.utc), self.interval)
        return self.hub.ingest_samples(samples, sim_namespace(scenario_id))["accepted"]

    async def run(self) -> None:
        while True:
            started = time.monotonic()
            for scenario_id in self.active():
                try:
                    await asyncio.to_thread(self.tick, scenario_id)
                except Exception:  # a broken tick must not stop the stream for every other scenario
                    log.exception("live simulator tick failed for %s", scenario_id)
                    self.hub.count("simulator_errors")
            self.ticks += 1
            await asyncio.sleep(max(0.05, self.interval - (time.monotonic() - started)))

    def start(self) -> None:
        if self.task is None:
            self.task = asyncio.get_running_loop().create_task(self.run(), name="telemetry-simulator")

    async def stop(self) -> None:
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None
