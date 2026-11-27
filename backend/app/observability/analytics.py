"""Deterministic analytics over interface history: baselines, forecasts and congestion risk.

All statistics are computed here, in code. Nothing in this module calls a model, and the results are compact summaries
(a few numbers per interface) so that an agent never needs raw telemetry in its context.
"""
import math
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

from app.network.models import LinkType
from app.network.repository import load_scenario, load_topology
from app.observability.simulation import (
    DOWN,
    SITE_GEO,
    STEP,
    UNKNOWN,
    UP,
    InterfaceHistory,
    history_end,
    interface_history,
    monitored_interfaces,
)

MAD_SCALE = 1.4826
FLOORS = {"utilization": 12.0, "latency": 0.08, "loss": 0.5}
THRESHOLDS = (80.0, 90.0)
T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36, 8: 2.31, 9: 2.26, 10: 2.23, 15: 2.13, 20: 2.09, 30: 2.04}


def t95(df: int) -> float:
    if df < 1:
        return T95[1]
    return T95[max(k for k in T95 if k <= df)]


def local(moment: datetime, site_id: str) -> datetime:
    return moment + timedelta(hours=SITE_GEO[site_id].utc_offset_hours)


def bucket(moment: datetime, site_id: str) -> tuple[bool, int]:
    """(weekend, half-hour of the local day): half-hour slots keep the morning ramp from biasing the expected value."""
    clock = local(moment, site_id)
    return clock.weekday() >= 5, clock.hour * 2 + clock.minute // 30


def finite(value: float) -> bool:
    return not math.isnan(value)


def quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    position = (len(ordered) - 1) * q
    low, high = math.floor(position), math.ceil(position)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def rounded(value: float | None, digits: int = 2) -> float | None:
    return None if value is None or math.isnan(value) else round(value, digits)


# ---------------------------------------------------------------- baselines

@dataclass(frozen=True)
class Band:
    median: float
    low: float
    high: float
    p10: float
    p90: float
    samples: int


def band_for(values: list[float], metric: str) -> Band | None:
    if len(values) < 6:
        return None
    median = statistics.median(values)
    mad = statistics.median(abs(v - median) for v in values) * MAD_SCALE
    floor = FLOORS[metric] * (median if metric == "latency" else 1)
    width = max(3 * mad, floor)
    return Band(median, max(0.0, median - width), median + width, quantile(values, 0.1), quantile(values, 0.9), len(values))


def training(history: InterfaceHistory, trend_per_day: float) -> dict[str, dict[tuple[bool, int], list[float]]]:
    """Seasonal buckets (weekday or weekend, local hour), with utilisation trend-adjusted to the window's level."""
    buckets: dict[str, dict[tuple[bool, int], list[float]]] = {"utilization": {}, "latency": {}, "loss": {}}
    for index in range(history.window_start_index):
        if history.status[index] != UP:
            continue
        key = bucket(history.at(index), history.site_id)
        days_before = (history.window_start_index - index) / 288
        for metric, series in (("utilization", history.utilization), ("latency", history.latency), ("loss", history.loss)):
            if finite(series[index]):
                value = series[index] + (trend_per_day * days_before if metric == "utilization" else 0.0)
                buckets[metric].setdefault(key, []).append(value)
    return buckets


@lru_cache(maxsize=1024)
def interface_baseline(scenario_id: str, interface_id: str) -> dict[str, Any]:
    history = interface_history(scenario_id, interface_id)
    trend = interface_forecast(scenario_id, interface_id).get("trend_per_day") or 0.0
    learned = training(history, trend)
    bands = {metric: {key: band_for(values, metric) for key, values in groups.items()} for metric, groups in learned.items()}
    anomalies, current = [], {}
    window = range(history.window_start_index, len(history))
    for index in window:
        moment = history.at(index)
        key = bucket(moment, history.site_id)
        if history.status[index] == DOWN:
            anomalies.append({"timestamp": moment.isoformat(), "metric": "oper_status", "value": "down", "expected": "up", "kind": "down"})
            continue
        if history.status[index] == UNKNOWN:
            anomalies.append({"timestamp": moment.isoformat(), "metric": "telemetry", "value": None, "expected": "sample", "kind": "gap"})
            continue
        for metric, series in (("utilization", history.utilization), ("latency", history.latency), ("loss", history.loss)):
            value, band = series[index], bands[metric].get(key)
            if band is None or not finite(value):
                continue
            current[metric] = (value, band)
            if value > band.high or value < band.low:
                anomalies.append({"timestamp": moment.isoformat(), "metric": metric, "value": round(value, 2),
                                  "expected": round(band.median, 2), "band": [round(band.low, 2), round(band.high, 2)],
                                  "kind": "above" if value > band.high else "below",
                                  "deviation": round((value - band.median) / max(band.high - band.median, 1e-6) * 3, 1)})
    # Collapse repeated points into one anomaly per metric and kind, keeping first/last and the extreme value.
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for item in anomalies:
        key = (item["metric"], item["kind"])
        if key not in merged:
            merged[key] = {**item, "first_seen": item["timestamp"], "last_seen": item["timestamp"], "points": 1}
        else:
            entry = merged[key]
            entry["last_seen"], entry["points"] = item["timestamp"], entry["points"] + 1
            if isinstance(item.get("deviation"), float) and abs(item["deviation"]) > abs(entry.get("deviation") or 0):
                entry.update(value=item["value"], expected=item["expected"], deviation=item["deviation"])
    profile = []
    for hour in range(24):
        band = bands["utilization"].get((False, hour * 2))
        profile.append({"hour": hour, "median": rounded(band.median if band else None, 1),
                        "p10": rounded(band.p10 if band else None, 1), "p90": rounded(band.p90 if band else None, 1)})
    last = len(history) - 1
    return {
        "interface_id": interface_id, "device_id": history.device_id, "site_id": history.site_id, "link_id": history.link_id,
        "training_points": sum(len(v) for v in learned["utilization"].values()), "trend_adjustment_per_day": round(trend, 3),
        "method": "Median and MAD per local half-hour (weekday and weekend apart) over 14 days, trend-adjusted; anomaly outside "
                  "median +/- max(3 x MAD, floor)",
        "window_status": {UP: "up", DOWN: "down", UNKNOWN: "no_data"}[history.status[last]],
        "current": {metric: {"value": round(value, 2), "expected": round(band.median, 2),
                             "band": [round(band.low, 2), round(band.high, 2)],
                             "within_band": band.low <= value <= band.high} for metric, (value, band) in current.items()},
        "anomalies": sorted(merged.values(), key=lambda a: (a["first_seen"], a["metric"])),
        "weekday_profile": profile,
    }


def scenario_baselines(scenario_id: str) -> list[dict[str, Any]]:
    return [interface_baseline(scenario_id, interface_id) for interface_id in monitored_interfaces(load_scenario(scenario_id))]


# ---------------------------------------------------------------- forecasting

def daily_peaks(history: InterfaceHistory) -> list[tuple[str, float, bool]]:
    days: dict[str, list[float]] = {}
    weekend: dict[str, bool] = {}
    for index in range(history.window_start_index):
        if history.status[index] != UP or not finite(history.utilization[index]):
            continue
        clock = local(history.at(index), history.site_id)
        day = clock.date().isoformat()
        days.setdefault(day, []).append(history.utilization[index])
        weekend[day] = clock.weekday() >= 5
    return [(day, quantile(values, 0.95), weekend[day]) for day, values in sorted(days.items()) if len(values) >= 48]


def linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float, float, float, float]:
    n = len(xs)
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs) or 1e-9
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / sxx
    intercept = mean_y - slope * mean_x
    residuals = [y - (intercept + slope * x) for x, y in zip(xs, ys)]
    s = math.sqrt(sum(r * r for r in residuals) / (n - 2)) if n > 2 else 0.0
    return slope, intercept, s, mean_x, sxx


@lru_cache(maxsize=1024)
def interface_forecast(scenario_id: str, interface_id: str, horizon_days: int = 30) -> dict[str, Any]:
    history = interface_history(scenario_id, interface_id)
    peaks = daily_peaks(history)
    workdays = [(day, value) for day, value, weekend in peaks if not weekend]
    result: dict[str, Any] = {"interface_id": interface_id, "device_id": history.device_id, "site_id": history.site_id,
                              "link_id": history.link_id, "speed_mbps": history.speed_mbps, "horizon_days": horizon_days,
                              "method": "OLS trend of weekday busy-hour peaks (p95) with a 95% prediction interval; "
                                        "next-24h profile from the last 7 days by local hour plus trend",
                              "observed": [{"day": day, "peak": round(value, 1), "weekend": weekend} for day, value, weekend in peaks]}
    if len(workdays) < 4:
        result.update(status="insufficient_history", trend_per_day=None, forecast=[], days_to=None, next_24h=[])
        return result
    last_day = datetime.fromisoformat(peaks[-1][0])
    xs = [(datetime.fromisoformat(day) - last_day).days for day, _ in workdays]
    ys = [value for _, value in workdays]
    slope, intercept, s, mean_x, sxx = linear_fit(xs, ys)
    t = t95(len(xs) - 2)
    forecast = []
    for ahead in range(1, horizon_days + 1):
        mean = intercept + slope * ahead
        margin = t * s * math.sqrt(1 + 1 / len(xs) + (ahead - mean_x) ** 2 / sxx)
        day = last_day + timedelta(days=ahead)
        forecast.append({"day": day.date().isoformat(), "peak": round(min(100, max(0, mean)), 1),
                         "low": round(min(100, max(0, mean - margin)), 1), "high": round(min(100, max(0, mean + margin)), 1),
                         "weekend": day.weekday() >= 5})
    today = intercept
    days_to = {}
    for threshold in THRESHOLDS:
        if today >= threshold:
            days_to[str(int(threshold))] = 0
        elif slope > 0.02:
            days_to[str(int(threshold))] = round((threshold - today) / slope, 1)
        else:
            days_to[str(int(threshold))] = None
    # Next 24 hours: the median of the last 7 days at each local hour, shifted by one day of trend.
    end, recent_start = len(history), max(0, history.window_start_index - 7 * 288)
    by_hour: dict[int, list[float]] = {}
    for index in range(recent_start, history.window_start_index):
        if history.status[index] == UP and finite(history.utilization[index]):
            clock = local(history.at(index), history.site_id)
            if clock.weekday() < 5:
                by_hour.setdefault(clock.hour, []).append(history.utilization[index])
    start = history.at(end - 1)
    next_24h = []
    for hour_ahead in range(1, 25):
        moment = start + timedelta(hours=hour_ahead)
        values = by_hour.get(local(moment, history.site_id).hour)
        if not values:
            continue
        expected = statistics.median(values) + slope * hour_ahead / 24
        spread = (quantile(values, 0.9) - quantile(values, 0.1)) / 2 + s
        next_24h.append({"timestamp": moment.isoformat(), "local_hour": local(moment, history.site_id).hour,
                         "expected": round(min(100, max(0, expected)), 1), "high": round(min(100, expected + spread), 1)})
    peak_hour = max(next_24h, key=lambda p: p["expected"]) if next_24h else None
    result.update(status="ok", trend_per_day=round(slope, 3), current_peak=round(today, 1), residual_sd=round(s, 2),
                  forecast=forecast, days_to=days_to, next_24h=next_24h, next_24h_peak=peak_hour)
    return result


# ---------------------------------------------------------------- congestion risk

def normal_tail(threshold: float, mean: float, sd: float) -> float:
    if sd <= 0:
        return 1.0 if mean >= threshold else 0.0
    return 0.5 * math.erfc((threshold - mean) / (sd * math.sqrt(2)))


CONGESTION_EVENTS = {"QOS_QUEUE_DROPS", "SLA_THRESHOLD_EXCEEDED"}


@lru_cache(maxsize=64)
def congestion(scenario_id: str) -> list[dict[str, Any]]:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    monitored = set(monitored_interfaces(dataset))
    results = []
    for link in topology.links:
        ends = [i for i in (link.a_interface_id, link.b_interface_id) if i in monitored]
        if not ends:
            continue
        forecasts = [interface_forecast(scenario_id, i) for i in ends]
        histories = [interface_history(scenario_id, i) for i in ends]
        down = any(h.status[len(h) - 1] == DOWN for h in histories)
        usable = [f for f in forecasts if f["status"] == "ok"]
        worst = max(usable, key=lambda f: f["next_24h_peak"]["expected"] if f.get("next_24h_peak") else 0, default=None)
        latest = [h.utilization[len(h) - 1] for h in histories if h.status[len(h) - 1] == UP]
        events = sorted({e.event_type for e in dataset.events if e.interface_id in ends and e.event_type in CONGESTION_EVENTS})
        entry: dict[str, Any] = {"link_id": link.link_id, "link_type": link.link_type.value, "interfaces": ends,
                                 "bandwidth_mbps": link.bandwidth_mbps, "current_utilization": rounded(max(latest), 1) if latest else None,
                                 "events": events}
        if down:
            entry.update(level="unavailable", probability=None, drivers=["The link is down; congestion risk does not apply"],
                         recommendation="Restore the link first")
            results.append(entry)
            continue
        if worst is None:
            entry.update(level="unknown", probability=None, drivers=["Not enough history to forecast"], recommendation=None)
            results.append(entry)
            continue
        peak = worst["next_24h_peak"]
        sd = max(worst["residual_sd"], (peak["high"] - peak["expected"]) / 1.28)
        probability = normal_tail(90.0, peak["expected"], sd)
        days_80, days_90 = worst["days_to"]["80"], worst["days_to"]["90"]
        drivers = [f"Predicted next-24h peak {peak['expected']}% at {peak['local_hour']:02d}:00 local (upper {peak['high']}%)"]
        if worst["trend_per_day"] and worst["trend_per_day"] > 0.05:
            drivers.append(f"Busy-hour peak growing {worst['trend_per_day']} points a day")
        if days_80 is not None and days_80 <= 30:
            drivers.append("Already above 80% at peak" if days_80 == 0 else f"Peak crosses 80% in about {days_80:g} days")
        if days_90 is not None and days_90 <= 30:
            drivers.append("Already above 90% at peak" if days_90 == 0 else f"Peak crosses 90% in about {days_90:g} days")
        if events:
            drivers.append("Queue drops or SLA breaches logged in the window: " + ", ".join(events))
        if probability >= 0.5 or (days_90 is not None and days_90 <= 7) or events:
            level = "high"
        elif probability >= 0.15 or (days_80 is not None and days_80 <= 14) or (days_90 is not None and days_90 <= 30):
            level = "medium"
        else:
            level = "low"
        recommendation = {"high": "Plan capacity now or apply QoS to protect priority traffic (advisory; no change is made)",
                          "medium": "Review capacity at the next planning cycle (advisory)", "low": None}[level]
        entry.update(level=level, probability=round(probability, 3), predicted_peak=peak, days_to=worst["days_to"],
                     trend_per_day=worst["trend_per_day"], drivers=drivers, recommendation=recommendation,
                     interface_id=worst["interface_id"])
        results.append(entry)
    order = {"high": 0, "medium": 1, "unavailable": 2, "low": 3, "unknown": 4}
    return sorted(results, key=lambda r: (order[r["level"]], -(r.get("probability") or 0), r["link_id"]))


def wan_interfaces(scenario_id: str) -> list[str]:
    topology = load_topology()
    wan = {i for l in topology.links if l.link_type == LinkType.WAN for i in (l.a_interface_id, l.b_interface_id)}
    return [i for i in monitored_interfaces(load_scenario(scenario_id)) if i in wan]


def history_window(scenario_id: str) -> tuple[datetime, datetime]:
    dataset = load_scenario(scenario_id)
    end = history_end(dataset)
    return end - STEP * 4031, end
