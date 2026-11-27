"""ARP spoofing and conflict detection. A gateway address answered by the wrong MAC is a spoofing indicator; two MACs
fighting over one host address is a conflict, and the DHCP lease table and static-host inventory decide which one owns it.
First-hop redundancy (virtual) MACs and MAC moves caused by a loop are not ARP problems."""
from collections import defaultdict
from ipaddress import IPv4Address

from app.protocols.engines.base import Context, Draft, EngineOutput, ref

MULTI_IP = 5
GRATUITOUS_FLOOD = 50


def analyze(ctx: Context) -> EngineOutput:
    arp = ctx.telemetry.arp
    out = EngineOutput(checked=["gateway addresses against the gateway MACs", "addresses claimed by more than one MAC", "MACs claiming many addresses",
                                "gratuitous ARP rate", "DHCP leases and static hosts for ownership"])
    events = [e for e in ctx.telemetry.events if e.protocol == "arp"]
    gateways = {str(g.ip): g for g in arp.gateways}
    leases = {str(l.ip_address): l for l in ctx.dataset.dhcp.leases if l.state.value == "active"}
    lease_by_mac = {l.mac_address: l for l in ctx.dataset.dhcp.leases}
    static = {str(h.ip): h for h in arp.static_hosts}
    static_by_mac = {h.mac: h for h in arp.static_hosts}
    pools = ctx.dataset.dhcp.pools
    alerts = ctx.telemetry.security.alerts if ctx.telemetry.security else []

    def owner(mac: str) -> str:
        if mac in lease_by_mac:
            lease = lease_by_mac[mac]
            return f"{lease.hostname or 'a DHCP client'} ({lease.ip_address})"
        if mac in static_by_mac:
            return f"{static_by_mac[mac].hostname} ({static_by_mac[mac].ip})"
        return "an unknown host"

    # ---- gateway impersonation
    for entry in arp.entries:
        gateway = gateways.get(str(entry.ip))
        if gateway is None or entry.mac == gateway.mac:
            continue
        floods = [e for e in events if e.kind == "GRATUITOUS" and str(e.ip) == str(entry.ip) and e.mac == entry.mac]
        related = [a for a in alerts if str(a.dst_ip) == str(entry.ip)]
        host = lease_by_mac.get(entry.mac)
        out.drafts.append(Draft(
            "ARP_GATEWAY_SPOOFING", "suspicious_indicator", "threat_indicator", "critical", f"Gateway {entry.ip} claimed by another MAC",
            f"{entry.device_id} sees the default gateway {entry.ip} (VLAN {entry.vlan_id}) at {entry.mac} on {entry.port or 'an access port'}, "
            f"not the gateway's {gateway.mac}. {entry.mac} belongs to {owner(entry.mac)}"
            + (f", which sent {sum(e.count for e in floods)} gratuitous ARP replies for it." if floods else ".")
            + " That host can intercept traffic leaving the VLAN; the data does not say why it is doing this.",
            "direct", [ref("arp_entries", entry.entry_id, entry.first_seen)] + [ref("protocol_events", e.event_id, e.timestamp) for e in floods][:2]
            + [ref("ids_alerts", a.alert_id, a.timestamp) for a in related][:2],
            "the gateway's address resolves to a MAC that is not the gateway's (and not a declared first-hop redundancy MAC)",
            device_id=entry.device_id, site_id=gateway.site_id, timestamp=entry.first_seen, affected_sites=[gateway.site_id],
            corroboration=int(bool(floods)) + int(bool(related)), hosts=[str(host.ip_address)] if host else [],
            facts={"gateway": str(entry.ip), "claimed_by": entry.mac, "gateway_mac": gateway.mac, "port": entry.port, "vlan": entry.vlan_id,
                   "host": owner(entry.mac), "gratuitous_replies": sum(e.count for e in floods)}))
    virtual = [g for g in arp.gateways if g.virtual]
    if virtual:
        out.notes.append(f"{len(virtual)} gateway(s) use a first-hop redundancy virtual MAC (for example {virtual[0].ip} at {virtual[0].mac}); "
                         "that is by design.")
    # ---- address conflicts
    conflicts = defaultdict(set)
    for event in events:
        if event.kind in ("DUPLICATE_ADDRESS", "MAC_CHANGE") and event.ip is not None and str(event.ip) not in gateways:
            conflicts[str(event.ip)].update(m for m in (event.mac, event.previous_mac) if m)
    by_ip = defaultdict(set)
    for entry in arp.entries:
        by_ip[str(entry.ip)].add(entry.mac)
    for ip, macs in by_ip.items():
        if len(macs) > 1 and ip not in gateways:
            conflicts[ip].update(macs)
    dhcp_conflicts = {str(e.ip_address): e for e in ctx.dataset.dhcp.events if e.event_type.value == "ip_conflict" and e.ip_address}
    for ip, macs in sorted(conflicts.items()):
        if len(macs) < 2:
            continue
        lease = leases.get(ip)
        in_range = any(p.contains(IPv4Address(ip)) for p in pools)
        static_host = static.get(ip)
        group = [e for e in events if str(e.ip) == ip]
        refs = [ref("protocol_events", e.event_id, e.timestamp) for e in group][:3] + [ref("arp_entries", en.entry_id, en.first_seen)
                                                                                         for en in arp.entries if str(en.ip) == ip][:2]
        if lease:
            refs.append(ref("dhcp_leases", f"{lease.pool_id}:{lease.ip_address}", lease.lease_start))
        if ip in dhcp_conflicts:
            refs.append(ref("dhcp_events", dhcp_conflicts[ip].event_id, dhcp_conflicts[ip].timestamp))
        site = ctx.site_of_ip(ip)
        known = lease is not None and static_host is not None and static_host.mac in macs and lease.mac_address in macs
        if known:
            cause = (f"{ip} is leased by DHCP to {lease.hostname or lease.mac_address} ({lease.mac_address}) and also configured statically "
                     f"on {static_host.hostname} ({static_host.mac})" + (", inside the DHCP range." if in_range else "."))
            out.drafts.append(Draft(
                "ARP_IP_CONFLICT", "confirmed_fault", "misconfiguration", "major", f"Duplicate IP address {ip}",
                f"{cause} The two hosts keep overwriting each other's ARP entry, so one of them drops off the network.",
                "two_sided", refs, "the DHCP lease table and the static-host inventory both claim the address for different MACs",
                device_id=group[0].device_id if group else None, site_id=site, timestamp=min((e.timestamp for e in group), default=None),
                affected_sites=[site] if site else [], corroboration=int(ip in dhcp_conflicts),
                facts={"ip": ip, "macs": sorted(macs), "dhcp_client": lease.mac_address, "static_host": static_host.hostname, "in_dhcp_range": in_range}))
        else:
            out.drafts.append(Draft(
                "ARP_IP_CONFLICT", "possible_explanation", "conflicting_state", "major", f"Address {ip} claimed by {len(macs)} MACs",
                f"{ip} is answered by {', '.join(sorted(macs))} ({'; '.join(owner(m) for m in sorted(macs))}). The owner is unclear from the data.",
                "measured", refs, "more than one MAC answers for the address, but neither the lease table nor the inventory settles who owns it",
                device_id=group[0].device_id if group else None, site_id=site, affected_sites=[site] if site else [],
                facts={"ip": ip, "macs": sorted(macs)}))
    # ---- one MAC claiming many addresses
    by_mac = defaultdict(set)
    for entry in arp.entries:
        by_mac[entry.mac].add(str(entry.ip))
    gateway_macs = {g.mac for g in arp.gateways}
    for mac_address, ips in sorted(by_mac.items()):
        if len(ips) >= MULTI_IP and mac_address not in gateway_macs:
            out.drafts.append(Draft(
                "ARP_MAC_MULTI_IP", "suspicious_indicator", "threat_indicator", "major", f"{mac_address} answers for {len(ips)} addresses",
                f"{mac_address} ({owner(mac_address)}) answers ARP for {len(ips)} addresses; outside a router or proxy that is a spoofing pattern.",
                "behavioural", [ref("arp_entries", e.entry_id, e.first_seen) for e in arp.entries if e.mac == mac_address][:6],
                "one MAC claims many addresses", facts={"mac": mac_address, "addresses": sorted(ips)[:10]}))
    flood = [e for e in events if e.kind == "GRATUITOUS" and e.count >= GRATUITOUS_FLOOD and str(e.ip) not in gateways]
    for event in flood:
        out.drafts.append(Draft(
            "ARP_GRATUITOUS_FLOOD", "suspicious_indicator", "threat_indicator", "minor", f"Gratuitous ARP flood for {event.ip}",
            f"{event.count} gratuitous ARP replies for {event.ip} from {event.mac}.", "behavioural", [ref("protocol_events", event.event_id, event.timestamp)],
            "gratuitous ARP far above normal", device_id=event.device_id, site_id=ctx.site_of.get(event.device_id), timestamp=event.timestamp,
            facts={"ip": str(event.ip), "mac": event.mac, "count": event.count}))
    return out

