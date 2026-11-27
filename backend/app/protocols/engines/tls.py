"""Certificate and TLS connectivity diagnosis: expired and soon-expiring certificates (with the handshake failures they
cause), names the certificate does not cover, incomplete chains, protocol-version failures, inspection CAs clients do
not trust, and sessions that receive a certificate other than the one the service owns (an interception indicator)."""
from collections import defaultdict
from datetime import timedelta

from app.protocols.engines.base import Context, Draft, EngineOutput, ref

SOON = timedelta(days=30)


def analyze(ctx: Context) -> EngineOutput:
    tls = ctx.telemetry.tls
    out = EngineOutput(checked=["certificate validity", "names covered by each certificate", "chain completeness", "handshake outcomes and alerts",
                                "certificate presented against the inventory", "inspection CA trust"])
    now = ctx.onset
    by_device = defaultdict(list)
    for cert in tls.certificates:
        by_device[cert.device_id].append(cert)
    ip_of = {str(d.management_ip): d.device_id for d in ctx.topology.devices}
    by_name = {}
    for cert in tls.certificates:
        for name in cert.sans:
            by_name[name] = cert
    handshakes = sorted(tls.handshakes, key=lambda h: h.timestamp)
    for cert in tls.certificates:
        failures = [h for h in handshakes if h.alert == "certificate_expired" and by_name.get(h.sni) is cert]
        sites = sorted({h.client_site_id for h in failures})
        if cert.not_after <= now or failures:
            out.drafts.append(Draft(
                "TLS_CERTIFICATE_EXPIRED", "confirmed_fault", "misconfiguration", "critical", f"{cert.common_name} certificate expired",
                f"The {cert.service} certificate for {cert.common_name} on {cert.device_id} expired at {cert.not_after:%Y-%m-%d %H:%M} UTC; "
                f"{len(failures)} handshake(s) since then failed with certificate_expired" + (f" from {', '.join(sites)}" if sites else "") +
                ". The network path is not involved.", "direct",
                [ref("certificates", cert.certificate_id, cert.not_after)] + [ref("tls_handshakes", h.handshake_id, h.timestamp) for h in failures][:4],
                "the certificate's validity ended and clients reject it with certificate_expired", device_id=cert.device_id, site_id="DC1",
                timestamp=cert.not_after, affected_sites=sites or ctx.sites_served_by([cert.device_id]), corroboration=int(bool(failures)),
                facts={"common_name": cert.common_name, "not_after": cert.not_after.isoformat(), "failed_handshakes": len(failures)}))
        elif cert.not_after - now <= SOON:
            out.notes.append(f"The {cert.service} certificate {cert.common_name} expires in {(cert.not_after - now).days} days "
                             f"({cert.not_after:%Y-%m-%d}): plan the renewal (not a fault today).")
        if not cert.chain_complete:
            out.drafts.append(Draft(
                "TLS_CHAIN_INCOMPLETE", "confirmed_fault", "misconfiguration", "major", f"{cert.common_name} sends an incomplete chain",
                f"{cert.device_id} does not send the intermediate certificate for {cert.common_name}; clients without it cached reject the server.",
                "direct", [ref("certificates", cert.certificate_id)], "the server's chain is incomplete", device_id=cert.device_id, site_id="DC1",
                affected_sites=ctx.sites_served_by([cert.device_id])))
    for handshake in handshakes:
        server = ip_of.get(str(handshake.server_ip))
        certs = by_device.get(server, [])
        if certs and handshake.result == "failure" and handshake.alert == "bad_certificate" and not any(handshake.sni in c.sans for c in certs):
            out.drafts.append(Draft(
                "TLS_NAME_MISMATCH", "confirmed_fault", "misconfiguration", "major", f"{handshake.sni} not covered by {server}'s certificate",
                f"Clients ask for {handshake.sni} but {server}'s certificate covers {', '.join(certs[0].sans)}.", "direct",
                [ref("tls_handshakes", handshake.handshake_id, handshake.timestamp)], "the requested name is not in the certificate",
                device_id=server, site_id="DC1", timestamp=handshake.timestamp, affected_sites=[handshake.client_site_id]))
            break
    unexpected = defaultdict(list)
    for handshake in handshakes:
        owned = by_name.get(handshake.sni)
        if owned is None or handshake.via_inspection or handshake.presented_fingerprint is None:
            continue
        if handshake.presented_fingerprint != owned.fingerprint:
            unexpected[(handshake.sni, handshake.client_site_id)].append(handshake)
    for (sni, site), group in sorted(unexpected.items()):
        clients = sorted({str(h.client_ip) for h in group})
        out.drafts.append(Draft(
            "TLS_UNEXPECTED_CERTIFICATE", "suspicious_indicator", "threat_indicator", "critical", f"{site} clients receive a foreign certificate for {sni}",
            f"{len(group)} session(s) from {len(clients)} {site} client(s) to {sni} were offered a certificate (fingerprint "
            f"{group[0].presented_fingerprint}) that is not the one {by_name[sni].device_id} owns, and no TLS inspection applies to them. "
            "Something between those clients and the server is presenting its own certificate.", "direct",
            [ref("tls_handshakes", h.handshake_id, h.timestamp) for h in group][:4] + [ref("certificates", by_name[sni].certificate_id)],
            "the presented certificate differs from the inventory and is not explained by inspection", site_id=site, timestamp=group[0].timestamp,
            affected_sites=[site], facts={"sni": sni, "presented": group[0].presented_fingerprint, "expected": by_name[sni].fingerprint,
                                                          "clients": clients, "alerts": sorted({h.alert for h in group if h.alert})}))
    inspection_failures = [h for h in handshakes if h.via_inspection and h.alert == "unknown_ca"]
    if inspection_failures:
        policy = tls.inspection[0] if tls.inspection else None
        out.drafts.append(Draft(
            "TLS_INSPECTION_UNTRUSTED", "confirmed_fault" if policy and policy.resign_ca not in tls.trusted_cas else "possible_explanation",
            "misconfiguration", "major", "Clients reject the TLS inspection certificate",
            f"{len(inspection_failures)} inspected session(s) failed with unknown_ca: clients do not trust "
            f"{policy.resign_ca if policy else 'the inspection CA'}.", "direct",
            [ref("tls_handshakes", h.handshake_id, h.timestamp) for h in inspection_failures][:4], "inspected sessions fail with unknown_ca",
            device_id=policy.device_id if policy else None, timestamp=inspection_failures[0].timestamp,
            affected_sites=sorted({h.client_site_id for h in inspection_failures})))
    versions = [h for h in handshakes if h.alert == "protocol_version"]
    if versions:
        out.drafts.append(Draft(
            "TLS_VERSION_MISMATCH", "confirmed_fault", "misconfiguration", "major", "TLS version mismatch",
            f"{len(versions)} handshake(s) failed with protocol_version: client and server share no TLS version.", "direct",
            [ref("tls_handshakes", h.handshake_id, h.timestamp) for h in versions][:4], "handshakes fail on protocol version",
            timestamp=versions[0].timestamp, affected_sites=sorted({h.client_site_id for h in versions})))
    return out
