"""OSPF link-state database analysis: duplicate router IDs, LSDB copies that disagree between routers, stale views,
MaxAge (flushed) LSAs, missing router LSAs and LSA churn."""
from collections import defaultdict
from datetime import timedelta
from statistics import median

from app.protocols.engines.base import Context, Draft, EngineOutput, ref

CHURN = 10  # updates for one LSA within ten minutes
STALE_SECONDS = 900


def analyze(ctx: Context) -> EngineOutput:
    lsdb = ctx.telemetry.ospf
    out = EngineOutput(checked=["router IDs", "LSDB copies across routers (sequence, checksum, age)", "MaxAge LSAs", "LSA flooding rate"])
    expected = sorted({n.device_id for n in ctx.dataset.routing.ospf_neighbors} | {n.neighbor_device_id for n in ctx.dataset.routing.ospf_neighbors})
    observers = sorted(set(lsdb.collected_from))
    missing = [d for d in expected if d not in observers]
    if missing:
        out.missing.append(f"No LSDB collected from {', '.join(missing)}")
    if len(observers) < 2:
        out.drafts.append(Draft(
            "OSPF_LSDB_PARTIAL", "insufficient_evidence", "coverage", "info", "Only one LSDB view collected",
            f"The LSDB was collected only from {', '.join(observers) or 'no router'}; database consistency between routers cannot be checked.",
            "none", [ref("ospf_lsas", lsa.lsa_id) for lsa in lsdb.lsas][:2], "comparing copies needs at least two routers' databases",
            device_id=observers[0] if observers else None, facts={"collected_from": observers, "missing": missing}))
    # ---- duplicate router IDs
    by_rid = defaultdict(list)
    for device, rid in lsdb.router_ids.items():
        by_rid[str(rid)].append(device)
    for rid, devices in sorted(by_rid.items()):
        if len(devices) < 2:
            continue
        events = [e for e in ctx.telemetry.events if e.protocol == "ospf" and e.kind == "DUPLICATE_ROUTER_ID"]
        updates = [u for u in lsdb.updates if str(u.advertising_router) == rid]
        configured = [d.device_id for d in ctx.topology.devices if str(d.router_id) == rid]
        newcomer = next((d for d in sorted(devices) if d not in configured), sorted(devices)[0])
        out.drafts.append(Draft(
            "OSPF_DUPLICATE_ROUTER_ID", "confirmed_fault", "misconfiguration", "critical", f"Duplicate OSPF router ID {rid}",
            f"{' and '.join(sorted(devices))} both use router ID {rid}. Each keeps re-originating the other's router LSA, so the "
            f"database never settles ({len(updates)} updates for that LSA in the window).", "direct",
            [ref("ospf_router_ids", d) for d in sorted(devices)] + [ref("protocol_events", e.event_id, e.timestamp) for e in events][:2]
            + [ref("lsa_updates", u.update_id, u.timestamp) for u in updates][:3],
            "two routers report the same router ID in their OSPF process", device_id=newcomer, site_id=ctx.site_of.get(newcomer),
            timestamp=min([u.timestamp for u in updates] + [e.timestamp for e in events], default=None),
            affected_sites=sorted({s for d in devices for s in ctx.sites_through(d)} - {"CORE"}),
            facts={"router_id": rid, "devices": sorted(devices), "originally_assigned_to": configured}, corroboration=len(events) > 0))
    # ---- copies of the same LSA across routers
    copies = defaultdict(dict)
    for lsa in lsdb.lsas:
        copies[(lsa.lsa_type, str(lsa.link_state_id), str(lsa.advertising_router))][lsa.observed_by] = lsa
    mismatched, stale_by = [], defaultdict(list)
    for key, views in sorted(copies.items()):
        if len(views) < 2:
            continue
        versions = {(v.sequence, v.checksum) for v in views.values() if v.age_seconds < 3600}
        if len(versions) > 1:
            mismatched.append((key, views))
        ages = [v.age_seconds for v in views.values()]
        middle = median(ages)
        for observer, view in views.items():
            if view.age_seconds - middle > STALE_SECONDS and view.age_seconds < 3600:
                stale_by[observer].append(view)
    if mismatched:
        key, views = mismatched[0]
        detail = ", ".join(f"{o}: seq {v.sequence:#x} checksum {v.checksum}" for o, v in sorted(views.items()))
        refs = [ref("ospf_lsas", v.lsa_id) for _, vs in mismatched for v in vs.values()][:8]
        out.drafts.append(Draft(
            "OSPF_LSDB_MISMATCH", "confirmed_fault", "conflicting_state", "major", f"OSPF databases disagree on {len(mismatched)} LSA(s)",
            f"Routers hold different copies of the {key[0]} LSA {key[1]} from {key[2]} ({detail}). Routers with different databases "
            "compute different paths.", "two_sided", refs, "the same LSA has different sequence numbers or checksums on different routers",
            device_id=None, timestamp=None, affected_sites=sorted({s for _, vs in mismatched for o in vs for s in ctx.sites_through(o)} - {"CORE"}),
            facts={"lsas": [f"{k[0]} {k[1]} adv {k[2]}" for k, _ in mismatched], "observers": sorted({o for _, vs in mismatched for o in vs})}))
    for observer, views in sorted(stale_by.items()):
        out.drafts.append(Draft(
            "OSPF_LSDB_STALE", "confirmed_fault", "anomaly", "major", f"{observer} holds an ageing copy of the database",
            f"{len(views)} LSAs on {observer} are more than {STALE_SECONDS // 60} minutes older than the same LSAs on its peers: it is no "
            "longer receiving refreshes, which happens when its adjacency is not FULL.", "measured",
            [ref("ospf_lsas", v.lsa_id) for v in views][:6], "LSA age on this router runs well ahead of every other copy",
            device_id=observer, site_id=ctx.site_of.get(observer), affected_sites=[s for s in ctx.sites_through(observer) if s != "CORE"][:3],
            facts={"stale_lsas": len(views)}))
    # ---- MaxAge and missing router LSAs
    maxage = defaultdict(list)
    for lsa in lsdb.lsas:
        if lsa.age_seconds >= 3600:
            maxage[str(lsa.advertising_router)].append(lsa)
    rid_owner = {str(d.router_id): d.device_id for d in ctx.topology.devices if d.router_id}
    for rid, views in sorted(maxage.items()):
        owner = rid_owner.get(rid)
        out.drafts.append(Draft(
            "OSPF_MAXAGE_LSA", "confirmed_fault", "anomaly", "major", f"Router LSA {rid} is being flushed",
            f"The {views[0].lsa_type} LSA from {rid}" + (f" ({owner})" if owner else "") + f" has reached MaxAge on {len(views)} router(s): "
            "the area has stopped hearing from that router.", "measured", [ref("ospf_lsas", v.lsa_id) for v in views][:6],
            "MaxAge LSAs are being removed from the database", device_id=owner, site_id=ctx.site_of.get(owner) if owner else None,
            affected_sites=[s for s in ctx.sites_through(owner) if s != "CORE"] if owner else [], facts={"router_id": rid, "observers": len(views)}))
    present = {str(l.advertising_router) for l in lsdb.lsas if l.lsa_type == "router" and l.age_seconds < 3600}
    for device in expected:
        rid = str(ctx.devices[device].router_id) if ctx.devices[device].router_id else None
        if rid and rid not in present and rid not in maxage and observers and device not in observers:
            out.drafts.append(Draft(
                "OSPF_ROUTER_LSA_MISSING", "possible_explanation", "anomaly", "major", f"No router LSA from {device}",
                f"None of the collected databases holds a router LSA from {device} ({rid}).", "inferred",
                [ref("ospf_lsas", l.lsa_id) for l in lsdb.lsas][:2], "the router's LSA is absent everywhere it should be flooded",
                device_id=device, site_id=ctx.site_of.get(device), facts={"router_id": rid}))
    # ---- churn
    updates_by_lsa = defaultdict(list)
    for update in lsdb.updates:
        updates_by_lsa[(update.lsa_type, str(update.link_state_id), str(update.advertising_router))].append(update)
    for key, updates in sorted(updates_by_lsa.items()):
        updates.sort(key=lambda u: u.timestamp)
        window = [u for u in updates if u.timestamp - updates[0].timestamp <= timedelta(minutes=10)]
        if len(window) >= CHURN:
            minutes = max(1, (window[-1].timestamp - window[0].timestamp).total_seconds() / 60)
            owner = rid_owner.get(key[2])
            out.drafts.append(Draft(
                "OSPF_LSA_CHURN", "confirmed_fault", "anomaly", "major", f"LSA {key[1]} re-flooded {len(window)} times",
                f"The {key[0]} LSA {key[1]} was re-originated {len(window)} times in {minutes:.0f} minutes (sequence "
                f"{window[0].sequence:#x} to {window[-1].sequence:#x}); normal refresh is every 30 minutes.", "measured",
                [ref("lsa_updates", u.update_id, u.timestamp) for u in window][:6], "the flooding rate is far above the refresh interval",
                device_id=owner, site_id=ctx.site_of.get(owner) if owner else None, timestamp=window[0].timestamp,
                affected_sites=sorted({s for d in by_rid.get(key[2], [owner] if owner else []) if d for s in ctx.sites_through(d)} - {"CORE"}),
                facts={"updates": len(window), "minutes": round(minutes, 1)}))
        elif updates:
            out.notes.append(f"{len(updates)} routine refresh(es) of the {key[0]} LSA {key[1]}: normal.")
    return out
