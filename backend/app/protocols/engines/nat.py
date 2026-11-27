"""NAT translation analysis: pool and port exhaustion with allocation failures, inside networks no rule translates,
rules shadowed by an earlier no-translate rule, and single hosts holding a large share of the pool."""
from app.protocols.engines.base import Context, Draft, EngineOutput, pct, ref

EXHAUSTED = 95.0
NEAR = 90.0
BUSY = 70.0
TOP_SHARE = 25.0


def analyze(ctx: Context) -> EngineOutput:
    nat = ctx.telemetry.nat
    out = EngineOutput(checked=["pool and port utilisation over time", "allocation failures", "rule coverage of every site's user networks",
                                "rule order", "top consumers"])
    for pool in nat.pools:
        capacity = pool.public_addresses * pool.ports_per_address
        samples = sorted((s for s in nat.samples if s.pool_id == pool.pool_id), key=lambda s: s.timestamp)
        if not samples:
            out.missing.append(f"No samples for pool {pool.pool_id}")
            continue
        latest = samples[-1]
        peak = max(samples, key=lambda s: s.active_translations)
        failures = sum(s.allocation_failures for s in samples)
        used = 100 * peak.active_translations / capacity
        trend = " → ".join(pct(100 * s.active_translations / capacity) for s in samples)
        refs = [ref("nat_samples", s.sample_id, s.timestamp) for s in samples][:4] + [ref("nat_pools", pool.pool_id)]
        site_list = sorted(nat.site_networks)
        if failures and used >= EXHAUSTED:
            first = next(s for s in samples if s.allocation_failures)
            logs = [e for e in ctx.dataset.events if e.device_id == pool.device_id and "NAT" in e.event_type]
            refs += [ref("events", e.event_id, e.timestamp) for e in logs][:2]
            out.drafts.append(Draft(
                "NAT_POOL_EXHAUSTED", "confirmed_fault", "anomaly", "critical", f"NAT pool {pool.pool_id} is exhausted",
                f"{pool.pool_id} on {pool.device_id} has {pool.public_addresses} public address(es) × {pool.ports_per_address:,} ports = "
                f"{capacity:,} translations; it reached {peak.active_translations:,} ({used:.0f}%) and refused {failures:,} new sessions "
                f"(utilisation {trend}).", "measured", refs, "the pool is full and the device logged allocation failures",
                device_id=pool.device_id, site_id=ctx.site_of.get(pool.device_id), timestamp=first.timestamp, affected_sites=site_list,
                corroboration=int(bool(logs)), facts={"capacity": capacity, "peak": peak.active_translations, "utilization_percent": round(used, 1), "allocation_failures": failures,
                       "public_addresses": pool.public_addresses}))
        elif used >= NEAR:
            out.drafts.append(Draft(
                "NAT_POOL_NEAR_EXHAUSTION", "possible_explanation", "performance", "major", f"NAT pool {pool.pool_id} nearly full",
                f"{pool.pool_id} peaked at {used:.0f}% of {capacity:,} translations with no failures yet ({trend}).", "measured", refs,
                "utilisation is close to the limit but nothing has been refused", device_id=pool.device_id, site_id=ctx.site_of.get(pool.device_id),
                timestamp=peak.timestamp, affected_sites=site_list, facts={"capacity": capacity, "utilization_percent": round(used, 1)}))
        elif used >= BUSY:
            out.notes.append(f"{pool.pool_id} is busy at {used:.0f}% with no allocation failures: within capacity.")
        for talker in (t for t in nat.top_talkers if t.pool_id == pool.pool_id and t.timestamp == latest.timestamp):
            share = 100 * talker.translations / capacity
            if share >= TOP_SHARE:
                out.drafts.append(Draft(
                    "NAT_TOP_CONSUMER", "possible_explanation", "anomaly", "major", f"{talker.inside_ip} holds {share:.0f}% of {pool.pool_id}",
                    f"{talker.inside_ip} holds {talker.translations:,} translations to {talker.destinations:,} destinations.", "measured",
                    [ref("nat_talkers", talker.talker_id, talker.timestamp)], "one inside host holds a large share of the pool",
                    device_id=pool.device_id, timestamp=talker.timestamp, hosts=[str(talker.inside_ip)],
                    facts={"inside_ip": str(talker.inside_ip), "translations": talker.translations, "share_percent": round(share, 1)}))
    rules = sorted((r for r in nat.rules if r.enabled), key=lambda r: r.order)
    for site, networks in sorted(nat.site_networks.items()):
        for network in networks:
            matching = next((r for r in rules if network.subnet_of(r.source)), None)
            if matching is None or matching.pool_id is None:
                out.drafts.append(Draft(
                    "NAT_RULE_MISSING", "confirmed_fault", "misconfiguration", "critical", f"No NAT for {site} users ({network})",
                    f"No enabled NAT rule translates {network}" + (f"; {matching.rule_id} matches first and does not translate." if matching else ".")
                    + f" {site} users cannot reach the internet.", "direct",
                    [ref("nat_rules", r.rule_id, r.last_modified) for r in rules][:4], "the site's user network has no translating rule",
                    device_id=nat.pools[0].device_id if nat.pools else None, site_id=site, affected_sites=[site],
                    timestamp=matching.last_modified if matching else None, facts={"network": str(network)}))
    for index, rule in enumerate(rules):
        for earlier in rules[:index]:
            if rule.source.subnet_of(earlier.source) and earlier.pool_id is None and rule.pool_id is not None:
                out.drafts.append(Draft(
                    "NAT_RULE_SHADOWED", "confirmed_fault", "misconfiguration", "major", f"NAT rule {rule.rule_id} is shadowed",
                    f"{earlier.rule_id} (order {earlier.order}, no translation) matches {rule.source} before {rule.rule_id} can translate it.",
                    "direct", [ref("nat_rules", earlier.rule_id, earlier.last_modified), ref("nat_rules", rule.rule_id, rule.last_modified)],
                    "an earlier no-translate rule fully covers a later translating rule", device_id=rule.device_id, timestamp=earlier.last_modified,
                    facts={"shadowed": rule.rule_id, "by": earlier.rule_id}))
    return out
