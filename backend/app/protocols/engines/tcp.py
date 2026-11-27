"""TCP retransmission analysis per site and service, before against after the onset: retransmissions (with whether they
depend on segment size), handshakes that do not complete, round-trip inflation and receiver zero windows. A zero window
with clean retransmission and RTT points at the server, not the network. Sites showing the same symptom on the same
service are reported together, because a shared symptom usually has one shared cause."""
from collections import defaultdict

from app.protocols.engines.base import Context, Draft, EngineOutput, mean, pct, ref

RETRANS_WARN = 2.0
SYN_WARN = 5.0
ZERO_WINDOW = 50


def sites_text(sites: list[str]) -> str:
    return sites[0] if len(sites) == 1 else f"{', '.join(sites[:-1])} and {sites[-1]}"


def analyze(ctx: Context) -> EngineOutput:
    tcp = ctx.telemetry.tcp
    out = EngineOutput(checked=["retransmissions before and after the onset, split by segment size", "handshake completion", "round-trip time",
                                "receiver zero windows"])
    groups = defaultdict(list)
    for sample in tcp.samples:
        groups[(sample.site_id, sample.service)].append(sample)
    hits = defaultdict(list)  # (code, service) -> per-site measurements
    for (site, service), samples in sorted(groups.items()):
        before = [s for s in samples if s.timestamp < ctx.onset]
        after = [s for s in samples if s.timestamp >= ctx.onset]
        if not after:
            continue
        refs = [ref("tcp_samples", s.sample_id, s.timestamp) for s in after][:2] + [ref("tcp_samples", s.sample_id, s.timestamp) for s in before][:1]
        base = {"site": site, "path": after[0].path_id, "server": after[0].server_device_id, "refs": refs, "at": after[0].timestamp}
        live = [s for s in after if s.flows > 0]
        if not live and mean([s.syn_retry_percent for s in after]) >= 99:
            hits[("TCP_HANDSHAKE_FAILURES", service)].append({**base, "outage": True, "before": mean([s.syn_retry_percent for s in before]), "after": 100.0})
            continue
        retrans_before, retrans_after = mean([s.retransmission_percent for s in before]), mean([s.retransmission_percent for s in live])
        syn_before, syn_after = mean([s.syn_retry_percent for s in before]), mean([s.syn_retry_percent for s in live])
        rtt_before, rtt_after = mean([s.rtt_ms for s in before]), mean([s.rtt_ms for s in live])
        zero = mean([s.zero_window_events for s in live])
        bulk = mean([s.bulk_retransmission_percent or 0 for s in live])
        small = mean([s.small_retransmission_percent or 0 for s in live])
        if retrans_after >= RETRANS_WARN and retrans_after >= 2 * max(retrans_before, 0.3):
            hits[("TCP_RETRANSMISSION_HIGH", service)].append({**base, "before": retrans_before, "after": retrans_after, "bulk": bulk, "small": small,
                                                               "size_dependent": bulk >= 3 * max(small, 0.1) and small < 1.0})
        if syn_after >= SYN_WARN and syn_after >= 3 * max(syn_before, 0.3):
            hits[("TCP_HANDSHAKE_FAILURES", service)].append({**base, "outage": False, "before": syn_before, "after": syn_after})
        if rtt_before and rtt_after >= rtt_before * 1.5 + 30:
            hits[("TCP_RTT_INFLATION", service)].append({**base, "before": rtt_before, "after": rtt_after})
        if zero >= ZERO_WINDOW and retrans_after < RETRANS_WARN and rtt_after < rtt_before * 1.5 + 30:
            hits[("TCP_ZERO_WINDOW", service)].append({**base, "zero": zero, "retrans": retrans_after})
    for (code, service), rows in sorted(hits.items()):
        sites = [r["site"] for r in rows]
        refs = [x for r in rows for x in r["refs"]][:8]
        at = min(r["at"] for r in rows)
        one = sites[0] if len(sites) == 1 else None
        per_site = "; ".join(f"{r['site']} {pct(r['before'])} → {pct(r['after'])}" for r in rows) if code != "TCP_ZERO_WINDOW" else ""
        if code == "TCP_RETRANSMISSION_HIGH":
            worst = max(r["after"] for r in rows)
            sized = all(r["size_dependent"] for r in rows)
            pattern = (f" Full-size segments lose {pct(max(r['bulk'] for r in rows))} but small ones under {pct(max(r['small'] for r in rows))}: "
                       "the loss depends on packet size." if sized else " Large and small segments are affected alike.")
            shared = " Several sites at once points at a segment their paths share." if len(sites) > 1 else ""
            out.drafts.append(Draft(
                code, "confirmed_fault", "performance", "critical" if worst >= 5 else "major", f"TCP retransmissions up on {sites_text(sites)} {service} traffic",
                f"Retransmissions on {service} traffic since the onset: {per_site}.{pattern}{shared}", "measured", refs,
                "a measured rise well above each site's own baseline", site_id=one, timestamp=at, affected_sites=sites, corroboration=min(len(sites) - 1, 2),
                facts={"service": service, "sites": sites, "after": {r["site"]: round(r["after"], 2) for r in rows}, "size_dependent": sized,
                       "paths": [r["path"] for r in rows]}))
        elif code == "TCP_HANDSHAKE_FAILURES":
            outage = all(r["outage"] for r in rows)
            text = (f"Since the onset no {service} TCP session from {sites_text(sites)} completes: every SYN goes unanswered."
                    if outage else f"New {service} sessions needing SYN retries since the onset: {per_site}. Something on the path drops or refuses new connections.")
            out.drafts.append(Draft(
                code, "confirmed_fault", "anomaly", "critical" if outage else "major",
                f"{'No' if outage else 'Failing'} {service} TCP handshakes from {sites_text(sites)}", text, "measured", refs,
                "handshake retries far above the baseline" if not outage else "complete loss of handshakes after the onset", site_id=one, timestamp=at,
                affected_sites=sites, corroboration=min(len(sites) - 1, 2), facts={"service": service, "sites": sites, "outage": outage,
                                                                                  "paths": [r["path"] for r in rows]}))
        elif code == "TCP_RTT_INFLATION":
            out.drafts.append(Draft(
                code, "confirmed_fault", "performance", "major", f"Round-trip time up on {sites_text(sites)} {service} traffic",
                "Round-trip time since the onset: " + "; ".join(f"{r['site']} {r['before']:.0f} → {r['after']:.0f} ms" for r in rows) + ".", "measured",
                refs, "round-trip time well above the baseline", site_id=one, timestamp=at, affected_sites=sites,
                facts={"service": service, "sites": sites}))
        else:
            server = rows[0]["server"]
            out.drafts.append(Draft(
                code, "possible_explanation", "performance", "major", f"{server or 'The server'} stops reading ({service})",
                f"About {mean([r['zero'] for r in rows]):.0f} zero-window events per interval from {server or 'the server'} on traffic from "
                f"{sites_text(sites)}, while retransmissions (under {pct(max(r['retrans'] for r in rows))}) and round-trip time stay normal: the "
                "network delivers the data but the receiving application is not keeping up.", "behavioural", refs,
                "zero windows with a clean path point at the receiver, not the network", device_id=server,
                site_id=ctx.site_of.get(server) if server else None, timestamp=at, affected_sites=sites, corroboration=min(len(sites) - 1, 2),
                facts={"service": service, "server": server, "sites": sites, "zero_windows": round(mean([r["zero"] for r in rows]))}))
    return out
