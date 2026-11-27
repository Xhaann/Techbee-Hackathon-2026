"""Wireless interference analysis from controller radio statistics: non-Wi-Fi interference (noise floor, interference
share, retries), co-channel contention, radar-driven channel changes, low SNR and rogue access points. A busy radio
with clean RF is reported as healthy."""
from collections import defaultdict

from app.protocols.engines.base import Context, Draft, EngineOutput, has_injection, mean, ref

NOISE = -85.0
INTERFERENCE = 25.0
RETRY = 20.0
BUSY = 70.0
LOW_SNR = 20.0


def analyze(ctx: Context) -> EngineOutput:
    wifi = ctx.telemetry.wireless
    out = EngineOutput(checked=["noise floor and non-Wi-Fi interference", "retries and channel utilisation", "co-channel neighbours",
                                "radar events", "signal-to-noise ratio", "rogue access points"])
    events = [e for e in ctx.telemetry.events if e.protocol == "wireless"]
    groups = defaultdict(list)
    for sample in wifi.samples:
        groups[(sample.ap_id, sample.band)].append(sample)
    site_of_ap = {ap.ap_id: ap.site_id for ap in wifi.access_points}
    interfered = defaultdict(list)
    busy_ok = []
    for (ap, band), samples in sorted(groups.items()):
        after = [s for s in samples if s.timestamp >= ctx.onset] or samples
        noise, share, retry = mean([s.noise_floor_dbm for s in after]), mean([s.non_wifi_interference for s in after]), mean([s.retry_percent for s in after])
        util, snr, cochannel = mean([s.channel_utilization for s in after]), mean([s.avg_snr_db for s in after]), max(s.co_channel_aps for s in after)
        site = site_of_ap.get(ap)
        refs = [ref("radio_samples", s.sample_id, s.timestamp) for s in after][:2]
        if noise > NOISE and share >= INTERFERENCE and retry >= RETRY:
            interfered[(site, band)].append((ap, noise, share, retry, util, snr, refs, after[0].timestamp))
        elif util >= BUSY and share < 10 and cochannel >= 2 and retry >= 15:
            out.drafts.append(Draft(
                "WIFI_CO_CHANNEL", "possible_explanation", "performance", "minor", f"Co-channel contention on {ap} {band}",
                f"{ap} {band} is {util:.0f}% busy with {cochannel} neighbours on the same channel and {retry:.0f}% retries, but little non-Wi-Fi "
                "noise: too many radios share the channel.", "measured", refs, "high utilisation and retries without interference",
                device_id=ap, site_id=site, timestamp=after[0].timestamp, affected_sites=[site] if site else []))
        elif snr < LOW_SNR and share < 10:
            out.drafts.append(Draft(
                "WIFI_LOW_SNR", "possible_explanation", "performance", "minor", f"Weak signal on {ap} {band}",
                f"Clients on {ap} {band} average {snr:.0f} dB SNR without interference: a coverage gap.", "measured", refs,
                "SNR below a usable level with a clean noise floor", device_id=ap, site_id=site, timestamp=after[0].timestamp,
                affected_sites=[site] if site else []))
        elif util >= BUSY and retry < 15 and snr >= 25:
            busy_ok.append(f"{ap} {band} ({util:.0f}% busy, {retry:.0f}% retries)")
    for (site, band), aps in sorted(interfered.items()):
        names = [a[0] for a in aps]
        noise = max(a[1] for a in aps)
        share = max(a[2] for a in aps)
        retry = max(a[3] for a in aps)
        snr = min(a[5] for a in aps)
        out.drafts.append(Draft(
            "WIFI_INTERFERENCE", "confirmed_fault", "anomaly", "major", f"Non-Wi-Fi interference on {band} at {site}",
            f"{', '.join(names)} on {band} see a noise floor up to {noise:.0f} dBm (normal about -94), {share:.0f}% of airtime taken by non-Wi-Fi "
            f"energy and {retry:.0f}% retries; SNR is down to {snr:.0f} dB." + (" More than one AP is affected, so the source is near them, not in "
                                                                                 "an AP." if len(names) > 1 else ""),
            "measured", [r for a in aps for r in a[6]][:6], "measured RF interference above thresholds on the radio", device_id=names[0], site_id=site,
            timestamp=min(a[7] for a in aps), affected_sites=[site] if site else [], corroboration=len(names) - 1,
            facts={"aps": names, "band": band, "noise_floor_dbm": noise, "interference_percent": share, "retry_percent": retry, "snr_db": snr}))
    radar = [e for e in events if e.kind == "DFS_RADAR"]
    by_ap = defaultdict(list)
    for event in radar:
        by_ap[event.device_id].append(event)
    for ap, group in sorted(by_ap.items()):
        site = site_of_ap.get(ap)
        out.drafts.append(Draft(
            "WIFI_DFS_CHANNEL_CHANGE", "possible_explanation", "anomaly", "minor", f"Radar forced {ap} off its channel {len(group)} time(s)",
            f"{ap} detected radar {len(group)} time(s) and changed 5 GHz channel each time; clients on that radio briefly disconnect.", "direct",
            [ref("protocol_events", e.event_id, e.timestamp) for e in group][:3], "the controller logged DFS radar events", device_id=ap, site_id=site,
            timestamp=group[0].timestamp, affected_sites=[site] if site else [], facts={"events": len(group)}))
    for rogue in wifi.rogues:
        injected = has_injection(rogue.ssid)
        ssid = ctx.text(rogue.ssid)
        if rogue.ssid in wifi.corporate_ssids or rogue.detected_on_wire:
            reason = "broadcasts a corporate SSID" if rogue.ssid in wifi.corporate_ssids else "is connected to our wired network"
            out.drafts.append(Draft(
                "WIFI_ROGUE_AP", "suspicious_indicator", "threat_indicator", "major", f"Rogue access point at {rogue.site_id}",
                f"An access point {rogue.bssid} ({ssid}) on channel {rogue.channel} {reason}.", "direct", [ref("rogue_aps", rogue.rogue_id, rogue.first_seen)],
                "an unmanaged AP impersonates us or is attached to our network", site_id=rogue.site_id, timestamp=rogue.first_seen,
                affected_sites=[rogue.site_id], injection=injected, facts={"bssid": rogue.bssid, "channel": rogue.channel}))
        else:
            out.notes.append(f"A neighbouring access point at {rogue.site_id} ({rogue.bssid}, channel {rogue.channel}) is not on our network and does not "
                             "use our SSIDs: no action needed." + (" Its SSID contained instruction-like text and was withheld." if injected else ""))
    if busy_ok:
        out.notes.append(f"Busy but healthy: {', '.join(busy_ok[:3])}. Clean RF and low retries.")
    return out
