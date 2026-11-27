"""Ten additional synthetic incident scenarios (SCN-01 to SCN-10), hardcoded and deterministic.

Each one changes the healthy baseline the way a real fault would: the core records (logs, interface counters, routing
tables and changes, firewall rules, DNS and DHCP) and the protocol and security telemetry, plus decoys that point
somewhere else and sites that stay healthy for comparison. They load through the same loader as every other scenario
(app.protocols.scenarios), so incidents, diagnosis, conversations, observability and the protocol engines all see them.

What a correct diagnosis should conclude lives in app/protocols/cards.py and the dataset's ground_truth block. Nothing
here, and nothing in the diagnostic code, reads those expectations.
"""
from datetime import timedelta

from app.protocols.baseline import between, mac, stamp, whole
from app.protocols.scenario_kit import Edit, Spec

ALL = ["NYC", "SIN", "BLR"]
WAN_IF = {"NYC": ("NYC-RTR-01:Gi0/0/0", "CORE-RTR-01:Gi0/0/2"), "SIN": ("SIN-RTR-01:Gi0/0/0", "CORE-RTR-01:Gi0/0/3"),
          "BLR": ("BLR-RTR-01:Gi0/0/0", "CORE-RTR-02:Gi0/0/2")}
NYC_PREFIXES = ["10.10.10.0/24", "10.10.20.0/24", "10.10.99.0/24"]


def tcp(e: Edit, sites: list[str], services: tuple[str, ...], **ranges: tuple[float, float]) -> None:
    """Sets after-onset TCP sample values for the given sites and services, each drawn from a (low, high) range."""
    for sample in e.t["tcp"]["samples"]:
        if sample["site_id"] in sites and sample["service"] in services and e.after(sample):
            for key, (low, high) in ranges.items():
                sample[key] = between(low, high, key, sample["sample_id"])


# =====================================================================================================================
# SCN-01  New York WAN circuit degrading and bouncing: BGP flaps, OSPF externals re-flooded, VPN and video churn
# =====================================================================================================================

def s01_core(e: Edit) -> None:
    nyc, core = WAN_IF["NYC"]
    e.event(-8, "NYC-RTR-01", "INTERFACE_ERRORS", "warning", "%INTERFACE-4-ERRORS: Gi0/0/0 input errors increased by 1840 in 60 s (CRC 1822)",
            nyc, "EVT-S01-001")
    e.event(-6, "CORE-FW-01", "POLICY_CHANGE", "notice",
            "Security policy committed by 'fwadmin': rule ALLOW-SAAS-CRM added at priority 105 (allow tcp 10.0.0.0/8 -> 0.0.0.0/0 port 8443)",
            None, "EVT-S01-002")
    e.firewall_rule("FWR-CORE-0105", "CORE-FW-01", 105, "ALLOW-SAAS-CRM", "allow", "tcp", "10.0.0.0/8", "0.0.0.0/0", 8443, -6)
    n = 2
    for cycle, start in enumerate((0, 3, 6, 9, 12), start=1):
        for minute, device, interface, event_type, severity, message in [
            (start, "NYC-RTR-01", nyc, "CARRIER_LOSS", "error", "%ETHPORT-3-IF_DOWN_LINK_FAILURE: Interface Gi0/0/0 is down (loss of signal)"),
            (start, "NYC-RTR-01", nyc, "LINK_DOWN", "error", "%LINK-3-UPDOWN: Interface Gi0/0/0, changed state to down"),
            (start, "CORE-RTR-01", core, "LINK_DOWN", "error", "%LINK-3-UPDOWN: Interface Gi0/0/2, changed state to down"),
            (start + 0.02, "NYC-RTR-01", None, "BGP_NEIGHBOR_DOWN", "notice", "%BGP-5-ADJCHANGE: neighbor 172.16.0.1 Down Interface flap"),
            (start + 0.02, "CORE-RTR-01", None, "BGP_NEIGHBOR_DOWN", "notice", "%BGP-5-ADJCHANGE: neighbor 172.16.0.2 Down Interface flap"),
            (start + 0.7, "NYC-RTR-01", nyc, "LINK_UP", "notice", "%LINK-3-UPDOWN: Interface Gi0/0/0, changed state to up"),
            (start + 0.7, "CORE-RTR-01", core, "LINK_UP", "notice", "%LINK-3-UPDOWN: Interface Gi0/0/2, changed state to up"),
            (start + 1.2, "NYC-RTR-01", None, "BGP_NEIGHBOR_UP", "notice", "%BGP-5-ADJCHANGE: neighbor 172.16.0.1 Up"),
            (start + 1.2, "CORE-RTR-01", None, "BGP_NEIGHBOR_UP", "notice", "%BGP-5-ADJCHANGE: neighbor 172.16.0.2 Up"),
        ]:
            n += 1
            e.event(minute, device, event_type, severity, message, interface, f"EVT-S01-{n:03d}")
    e.event(1, "NYC-RTR-01", "WAN_PROBE_FAILURE", "warning", "%TRACK-6-STATE: 10 ip sla 10 reachability Up -> Down (target 172.16.0.1)", nyc,
            "EVT-S01-050")
    e.event(14, "NYC-RTR-01", "WAN_PROBE_RECOVERED", "notice", "%TRACK-6-STATE: 10 ip sla 10 reachability Down -> Up (target 172.16.0.1)", nyc,
            "EVT-S01-051")
    for interface in (nyc, core):
        e.stats(interface, (5,), in_errors=2140, in_drops=690, packet_loss_percent=6.8, latency_ms=139.4, uptime_seconds=95)
        e.stats(interface, (15,), in_errors=1960, in_drops=640, packet_loss_percent=6.1, latency_ms=137.8, uptime_seconds=170)
    change = 0
    for start in (0, 3, 6, 9, 12):
        for prefix in NYC_PREFIXES:
            change += 1
            e.route_change(f"RC-S01-{change:03d}", start + 0.02, "CORE-RTR-01", prefix, "withdrawn", "172.16.0.2", None)
            change += 1
            e.route_change(f"RC-S01-{change:03d}", start + 1.2, "CORE-RTR-01", prefix, "added", None, "172.16.0.2")
    for device, peer in (("NYC-RTR-01", "CORE-RTR-01"), ("CORE-RTR-01", "NYC-RTR-01")):
        e.bgp_neighbor(device, peer, last_state_change=e.at(13.2))
    nyc_clients = e.lease_ips("NYC")[:4]
    for index, client in enumerate(nyc_clients):
        e.dns(f"DNS-Q-S01-{index + 1:02d}", 0.3 + index * 3, client, "10.100.100.10", "erp.corp.example.com", "timeout")
    e.incident("New York keeps dropping off the network for a minute at a time",
               "Calls, ERP and the all-hands video drop every few minutes in New York, then come back. A firewall change was made this morning.",
               "wan_connectivity_failure", "p1", ["NYC"], ["Drops every few minutes", "Calls and ERP cut out", "All-hands video freezes",
                                                            "Firewall change this morning"], number=401)
    e.truth("Carrier A circuit WAN-NYC-0001 (LNK-WAN-NYC) is degrading: CRC errors, then five losses of signal in twelve minutes. Each bounce "
            "resets the BGP session to CORE-RTR-01, withdraws and re-announces the New York prefixes, re-floods their OSPF externals, "
            "breaks the backup VPN and the video tree. The CORE-FW-01 policy change is unrelated.",
            ["NYC-RTR-01"], ["NYC"], ["PATH-NYC-APPLICATION", "PATH-NYC-DNS", "PATH-NYC-INTERNET"], ["LNK-WAN-NYC"])


def s01_telemetry(e: Edit) -> None:
    bgp = e.t["bgp"]
    n = 0
    for start in (0, 3, 6, 9, 12):
        for action, offset in (("withdraw", 0.02), ("announce", 1.2)):
            for prefix in NYC_PREFIXES:
                n += 1
                bgp["updates"].append({"update_id": f"BU-S01-{n:03d}", "timestamp": e.at(start + offset), "device_id": "CORE-RTR-01",
                                       "peer_device_id": "NYC-RTR-01", "prefix": prefix, "action": action,
                                       "as_path": [65010] if action == "announce" else []})
    for session in bgp["sessions"]:
        if "NYC-RTR-01" in (session["device_id"], session["peer_device_id"]):
            session["last_change"] = e.at(13.2)
    ospf = e.t["ospf"]
    n = 0
    for start in (0, 3, 6, 9, 12):
        for network in ("10.10.10.0", "10.10.20.0", "10.10.99.0"):
            for step, offset in enumerate((0.05, 1.25)):
                n += 1
                ospf["updates"].append({"update_id": f"LSU-S01-{n:03d}", "timestamp": e.at(start + offset), "observed_by": "CORE-RTR-02",
                                        "lsa_type": "external", "link_state_id": network, "advertising_router": "10.255.0.1",
                                        "sequence": 0x80000000 + 100 + n})
    for tunnel in e.t["ipsec"]["tunnels"]:
        if "NYC-RTR-01" in (tunnel["device_id"], tunnel["peer_device_id"]):
            tunnel.update(dpd_timeouts=5, last_change=e.at(13.5))
    e.proto_event(0.4, "ipsec", "DPD_TIMEOUT", "CORE-FW-01", "Dead peer detection: 198.51.100.10 not responding", event_id="PE-S01-01",
                  peer="NYC-RTR-01", count=5)
    tcp(e, ["NYC"], ("application", "internet"), retransmission_percent=(5, 7), syn_retry_percent=(6, 9), rtt_ms=(140, 160))
    for sample in e.t["tcp"]["samples"]:
        if sample["site_id"] == "NYC" and e.after(sample):
            sample["bulk_retransmission_percent"] = round(sample["retransmission_percent"] * 1.04, 2)
            sample["small_retransmission_percent"] = round(sample["retransmission_percent"] * 0.96, 2)
    for neighbour in e.t["multicast"]["neighbors"]:
        if {neighbour["device_id"], neighbour["neighbor_device_id"]} == {"CORE-RTR-01", "NYC-RTR-01"}:
            neighbour["last_change"] = e.at(13.3)
    for mroute in e.t["multicast"]["mroutes"]:
        if mroute["device_id"] == "NYC-RTR-01":
            mroute["packets_per_second"] = 182.0
    probes = e.t["mtu"]["probes"]
    for probe in probes:
        if probe["source_device_id"] == "NYC-RTR-01":
            probe.update(timestamp=e.at(3.1 + probe["size"] / 10000), probe_id=f"{probe['probe_id']}|s01",
                         result="timeout" if probe["size"] == 1400 else "ok")


# =====================================================================================================================
# SCN-02  Unexpected origin AS for half of Singapore's users (lab peering on NYC-RTR-01)
# =====================================================================================================================

S02_PREFIX = "10.20.10.96/28"


def s02_core(e: Edit) -> None:
    e.command(-6, "NYC-RTR-01", "labadmin", "router bgp 65010 ; neighbor 10.10.99.251 remote-as 64999", "EVT-S02-001")
    e.event(-5, "NYC-RTR-01", "BGP_NEIGHBOR_UP", "notice", "%BGP-5-ADJCHANGE: neighbor 10.10.99.251 Up", None, "EVT-S02-002")
    e.route("NYC-RTR-01", S02_PREFIX, "bgp", "10.10.99.251", "NYC-RTR-01:Gi0/0/1.99", 20)
    e.route("CORE-RTR-01", S02_PREFIX, "bgp", "172.16.0.2", "CORE-RTR-01:Gi0/0/2", 20)
    e.route("CORE-RTR-02", S02_PREFIX, "ospf", "10.0.0.9", "CORE-RTR-02:Te0/0/1", 110, 20)
    e.route("CORE-SW-01", S02_PREFIX, "ospf", "10.0.0.1", "CORE-SW-01:Te1/0/1", 110, 20)
    e.route("BLR-RTR-01", S02_PREFIX, "ospf", "172.16.0.9", "BLR-RTR-01:Gi0/0/0", 110, 30)
    e.route_change("RC-S02-001", 0, "CORE-RTR-01", S02_PREFIX, "added", None, "172.16.0.2")
    e.route_change("RC-S02-002", 0.4, "CORE-RTR-02", S02_PREFIX, "added", None, "10.0.0.9", "ospf")
    lower = [ip for ip in e.lease_ips("SIN") if 96 <= int(ip.split(".")[-1]) <= 111][:4]
    for index, client in enumerate(lower):
        e.dns(f"DNS-Q-S02-{index + 1:02d}", 1 + index * 3.5, client, "10.100.100.10", "erp.corp.example.com", "timeout")
    upper = [ip for ip in e.lease_ips("SIN") if int(ip.split(".")[-1]) >= 112][:2]
    for index, client in enumerate(upper):
        e.dns(f"DNS-Q-S02-{index + 11:02d}", 2 + index * 4, client, "10.100.100.10", "erp.corp.example.com", "noerror", ["10.100.100.40"], 168.4)
    for minute in (-11, 7):
        e.event(minute, "SIN-SW-01", "STP_TOPOLOGY_CHANGE", "informational", "%SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 10", None,
                f"EVT-S02-{10 + (minute > 0):03d}")
    e.incident("Some Singapore users can't reach ERP or the file shares",
               "About half of the Singapore desktops can't reach ERP, file shares or DNS since around 09:00; the rest are fine. Wi-Fi has been busy all morning.",
               "protocol_fault", "p2", ["SIN"], ["Half of the desktops affected", "ERP and DNS time out", "Other half fine", "Wi-Fi busy"], number=402)
    e.truth("A lab router (private AS64999) peered with NYC-RTR-01 advertises 10.20.10.96/28, a more-specific of Singapore's user subnet "
            "registered to AS65020. CORE-RTR-01 prefers it, so return traffic for about half of Singapore's DHCP clients (.96-.111) goes to the New York lab. "
            "Configuration error, not an attack, but the data alone cannot show intent.",
            ["NYC-RTR-01"], ["SIN"], ["PATH-SIN-APPLICATION", "PATH-SIN-DNS", "PATH-SIN-INTERNET"])


def s02_telemetry(e: Edit) -> None:
    bgp = e.t["bgp"]
    for route in bgp["routes"]:
        if route["prefix"] == S02_PREFIX and route["device_id"] == "CORE-RTR-01":
            route.update(as_path=[65010, 64999], origin_asn=64999, learned_at=e.at(0))
    bgp["routes"] = [r for r in bgp["routes"] if not (r["prefix"] == S02_PREFIX and r["device_id"] == "NYC-RTR-01")]
    bgp["routes"].append({"route_id": f"NYC-RTR-01|{S02_PREFIX}|lab", "device_id": "NYC-RTR-01", "prefix": S02_PREFIX, "next_hop": "10.10.99.251",
                          "as_path": [64999], "origin_asn": 64999, "learned_at": e.at(-5)})
    bgp["updates"].append({"update_id": "BU-S02-001", "timestamp": e.at(0), "device_id": "CORE-RTR-01", "peer_device_id": "NYC-RTR-01",
                           "prefix": S02_PREFIX, "action": "announce", "as_path": [65010, 64999]})
    tcp(e, ["SIN"], ("application", "internet"), syn_retry_percent=(38, 52), retransmission_percent=(3, 4.5))
    for sample in e.t["wireless"]["samples"]:
        if sample["ap_id"].startswith("SIN") and sample["band"] == "5GHz":
            sample.update(channel_utilization=between(74, 79, "busy", sample["sample_id"]), clients=whole(44, 58, "c", sample["sample_id"]))


# =====================================================================================================================
# SCN-03  A switch with bridge priority 0 plugged into Bengaluru takes the spanning-tree root
# =====================================================================================================================

ROGUE_BRIDGE = "02:de:5c:00:00:07"


def s03_core(e: Edit) -> None:
    e.event(-2, "BLR-SW-01", "LINK_UP", "notice", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up", None, "EVT-S03-001")
    e.event(-1.9, "BLR-SW-01", "STP_ROOT_CHANGE", "warning",
            f"%SPANTREE-6-ROOTCHANGE: Root Changed for vlan 10: New Root Port is GigabitEthernet1/0/7. New Root Mac Address is {ROGUE_BRIDGE}",
            None, "EVT-S03-002")
    for index, minute in enumerate((-1, 1, 3, 5, 8, 11, 14)):
        e.event(minute, "BLR-SW-01", "STP_TOPOLOGY_CHANGE", "warning", "%SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 10", None,
                f"EVT-S03-{index + 3:03d}")
    e.drop_events("BLR-SW-01", "STP_STABLE", after=-2)
    e.event(-9, "DC1-SRV-DHCP-01", "SERVICE_HEALTH", "warning", "Kea DHCP: pool DHCP-BLR-USERS 82% utilised (41 of 50 addresses)", None,
            "EVT-S03-020")
    e.stats("BLR-SW-01:Gi1/0/24", (5, 15), in_drops=2400, out_drops=3100)
    e.stats("BLR-RTR-01:Gi0/0/1", (5, 15), in_drops=2600, out_drops=2900)
    e.incident("Bengaluru users see short freezes every few minutes",
               "Bengaluru desktops freeze for a few seconds every couple of minutes since about 08:58; someone set up a new desk this morning. DHCP "
               "monitoring also warned the user pool is filling up.", "protocol_fault", "p3", ["BLR"],
               ["Freezes every few minutes", "New desk set up this morning", "DHCP pool warning"], number=403)
    e.truth(f"A small managed switch with bridge priority 0 ({ROGUE_BRIDGE}) was plugged into BLR-SW-01 Gi1/0/7, a port without BPDU guard. "
            "It became spanning-tree root for VLAN 10 and its unstable link keeps triggering topology changes that flush MAC tables. The DHCP "
            "pool warning is real but unrelated (82%, not exhausted).", ["BLR-SW-01"], ["BLR"], ["PATH-BLR-APPLICATION", "PATH-BLR-DNS"])


def s03_telemetry(e: Edit) -> None:
    stp = e.t["stp"]
    state = next(v for v in stp["vlans"] if v["device_id"] == "BLR-SW-01" and v["vlan_id"] == 10)
    state.update(root_mac=ROGUE_BRIDGE, root_priority=0, root_port="Gi1/0/7", topology_changes=state["topology_changes"] + 44,
                 last_topology_change=e.at(14), tc_source_port="Gi1/0/7")
    stp["ports"].append({"port_id": "BLR-SW-01|Gi1/0/7|10", "device_id": "BLR-SW-01", "port": "Gi1/0/7", "vlan_id": 10, "role": "root",
                         "state": "forwarding", "edge": False, "bpdu_guard": False})
    for port in stp["ports"]:
        if port["device_id"] == "BLR-SW-01" and port["port"] == "Gi1/0/24" and port["vlan_id"] == 10:
            port["role"] = "designated"
    e.proto_event(-1.9, "stp", "ROOT_CHANGE", "BLR-SW-01", f"VLAN 10 root moved to {ROGUE_BRIDGE} (priority 0) via Gi1/0/7", event_id="PE-S03-01",
                  port="Gi1/0/7", vlan_id=10)
    e.proto_event(1, "stp", "TOPOLOGY_CHANGE", "BLR-SW-01", "Topology change notifications on VLAN 10 received on Gi1/0/7", event_id="PE-S03-02",
                  port="Gi1/0/7", vlan_id=10, count=44)
    tcp(e, ["BLR"], ("application", "internet"), retransmission_percent=(2.6, 3.8))


# =====================================================================================================================
# SCN-04  New York voice VLAN deleted during a clean-up, plus an unrelated printer address conflict
# =====================================================================================================================

def s04_core(e: Edit) -> None:
    e.command(-5, "NYC-SW-01", "netops", "no vlan 20", "EVT-S04-001")
    e.command(-4.8, "NYC-SW-01", "netops", "interface Gi1/0/24 ; switchport trunk allowed vlan 10,99", "EVT-S04-002")
    e.event(-4.7, "NYC-SW-01", "VLAN_INACTIVE", "warning", "%SW_VLAN-4-VLAN_NOT_FOUND: Access VLAN 20 on Gi1/0/3 does not exist; port inactive",
            "NYC-SW-01:Gi1/0/3", "EVT-S04-003")
    e.event(-3, "DC1-SRV-DHCP-01", "SERVICE_HEALTH", "warning", "Kea DHCP: high CPU 91% during lease file compaction", None, "EVT-S04-004")
    e.core["dhcp"]["events"] = [ev for ev in e.core["dhcp"]["events"] if not (ev["pool_id"] == "DHCP-NYC-VOICE" and ev["timestamp"] > e.at(-5))]
    ip, lease_mac = e.lease_ip("NYC", 6), e.lease_mac("NYC", 6)
    pool = next(p for p in e.core["dhcp"]["pools"] if p["pool_id"] == "DHCP-NYC-USERS")
    e.core["dhcp"]["events"].append({"event_id": "DHCP-EVT-S04-001", "timestamp": e.at(4), "server_device_id": pool["server_device_id"],
                                     "pool_id": "DHCP-NYC-USERS", "event_type": "ip_conflict", "mac_address": lease_mac, "ip_address": ip,
                                     "message": f"Lease check: {ip} answered ping from another host after it was leased to {lease_mac}"})
    e.incident("New York desk phones have no network, and one PC keeps disconnecting",
               "Since a switch clean-up this morning New York desk phones show 'no network'. Separately one desktop drops off every few minutes. "
               "The DHCP server raised a CPU warning.", "protocol_fault", "p2", ["NYC"],
               ["Phones have no IP address", "One desktop keeps disconnecting", "DHCP server CPU warning", "Switch clean-up this morning"], number=404)
    e.truth("A VLAN clean-up on NYC-SW-01 deleted VLAN 20 from the switch and removed it from the uplink trunk, so phones in VLAN 20 never "
            "reach the router's DHCP relay. Independently, a printer was given a static address already leased to a desktop. The DHCP "
            "server's CPU warning is a red herring.", ["NYC-SW-01"], ["NYC"], ["PATH-NYC-DHCP"])


def s04_telemetry(e: Edit) -> None:
    for database in e.t["vlan"]["databases"]:
        if database["device_id"] == "NYC-SW-01":
            database["vlans"] = [1, 10, 99]
    for port in e.t["vlan"]["ports"]:
        if port["device_id"] == "NYC-SW-01":
            port["allowed_vlans"] = [10, 99]
    stp = e.t["stp"]
    stp["vlans"] = [v for v in stp["vlans"] if not (v["device_id"] == "NYC-SW-01" and v["vlan_id"] == 20)]
    stp["ports"] = [p for p in stp["ports"] if not (p["device_id"] == "NYC-SW-01" and p["vlan_id"] == 20)]
    ip, lease_mac = e.lease_ip("NYC", 6), e.lease_mac("NYC", 6)
    printer = mac("printer2", "NYC")
    e.t["arp"]["static_hosts"].append({"ip": ip, "mac": printer, "hostname": "nyc-prn-02"})
    for entry in e.t["arp"]["entries"]:
        if entry["ip"] == ip:
            entry.update(mac=printer, last_seen=e.at(11))
    e.proto_event(4, "arp", "DUPLICATE_ADDRESS", "NYC-RTR-01", f"Duplicate address {ip} on Gi0/0/1.10, sourced by {printer}", event_id="PE-S04-01",
                  ip=ip, mac=printer, previous_mac=lease_mac, vlan_id=10, count=11)


# =====================================================================================================================
# SCN-05  A no-NAT rule above the PAT rule on the internet edge; DNS forwarding fails as a side effect
# =====================================================================================================================

def s05_core(e: Edit) -> None:
    e.event(-3, "CORE-FW-01", "POLICY_CHANGE", "notice",
            "NAT policy committed by 'fwadmin': rule NONAT-PARTNER-VPN (no translation, source 10.0.0.0/8) added at position 50 (CHG-5120)",
            None, "EVT-S05-001")
    for index, (server, minute) in enumerate((("DC1-SRV-DNS-01", 1), ("DC1-SRV-DNS-02", 1.5), ("DC1-SRV-DNS-01", 9))):
        e.event(minute, server, "DNS_FORWARDER_TIMEOUT", "warning", "named: forwarder 198.51.100.53#53 not responding (timed out)", None,
                f"EVT-S05-{index + 2:03d}")
    e.stats("CORE-FW-01:ethernet1/1", (5, 15), utilization_percent=7.4)
    clients = e.lease_ips("NYC")[:2] + e.lease_ips("SIN")[:1] + e.lease_ips("BLR")[:1]
    for index, client in enumerate(clients):
        e.dns(f"DNS-Q-S05-{index + 1:02d}", 2 + index * 3, client, "10.100.100.10", "www.example.org", "servfail", response_ms=3004.2)
        e.dns(f"DNS-Q-S05-{index + 11:02d}", 2.5 + index * 3, client, "10.100.100.10", "erp.corp.example.com", "noerror", ["10.100.100.40"], 74.1)
    e.incident("Internet down at every office; DNS errors too",
               "No office can open external websites since about 09:00. Internal ERP works. Users also report DNS errors for external sites.",
               "protocol_fault", "p1", ALL, ["No external websites", "ERP works", "DNS errors for external names", "All offices"], number=405)
    e.truth("NAT rule NONAT-PARTNER-VPN, added at position 50 on CORE-FW-01 for a partner VPN, exempts all of 10.0.0.0/8 from translation and "
            "shadows the PAT rule. Internet sessions leave with private source addresses and replies never return. The DNS errors are a "
            "consequence: the DNS servers' forwarders are on the internet too.", ["CORE-FW-01"], ["BLR", "NYC", "SIN"],
            ["PATH-BLR-INTERNET", "PATH-NYC-INTERNET", "PATH-SIN-INTERNET"])


def s05_telemetry(e: Edit) -> None:
    nat = e.t["nat"]
    nat["rules"].append({"rule_id": "NONAT-PARTNER-VPN", "device_id": "CORE-FW-01", "order": 50, "source": "10.0.0.0/8", "pool_id": None,
                         "enabled": True, "last_modified": e.at(-3)})
    for sample in nat["samples"]:
        if e.after(sample):
            sample["active_translations"] = whole(90, 160, sample["sample_id"])
    for talker in nat["top_talkers"]:
        if e.after(talker):
            talker.update(translations=whole(0, 3, talker["talker_id"]), destinations=0)
    for sample in e.t["tcp"]["samples"]:
        if sample["service"] == "internet" and e.after(sample):
            sample.update(flows=0, retransmission_percent=0.0, bulk_retransmission_percent=0.0, small_retransmission_percent=0.0, syn_retry_percent=100.0)
    # Inspected internet sessions never complete a handshake once NAT is bypassed, so none are logged after the onset.
    e.t["tls"]["handshakes"] = [h for h in e.t["tls"]["handshakes"] if not (h.get("via_inspection") and e.after(h))]


# =====================================================================================================================
# SCN-06  Hub VPN changes on CORE-FW-01: New York PSK rotated on one side; Bengaluru return route deleted
# =====================================================================================================================

def s06_core(e: Edit) -> None:
    e.event(-8, "CORE-FW-01", "POLICY_CHANGE", "notice", "IKE gateway GW-NYC-BACKUP edited by fwadmin: pre-shared key rotated (CHG-5203)", None,
            "EVT-S06-001")
    e.event(-4, "CORE-FW-01", "POLICY_CHANGE", "notice",
            "Virtual router default: static route 10.30.0.0/16 via tunnel.30 deleted by fwadmin (CHG-5204, route clean-up)", None, "EVT-S06-002")
    e.event(-7, "NYC-RTR-01", "VPN_TUNNEL_DOWN", "notice", "%IKEV2-5-SA_DOWN: Remote 203.0.113.2:500 SA DOWN (AUTHENTICATION_FAILED)", None,
            "EVT-S06-003")
    e.event(3, "BLR-RTR-01", "WAN_PROBE_FAILURE", "warning", "%TRACK-6-STATE: 30 ip sla 30 reachability Up -> Down (target 10.100.100.40 via tunnel)",
            None, "EVT-S06-004")
    e.event(-12, "DC1-FW-01", "CONTENT_UPDATE", "informational", "Threat content update installed successfully", None, "EVT-S06-005")
    e.incident("Backup VPN alarms for New York and Bengaluru after firewall changes",
               "Monitoring shows the New York backup VPN down and the Bengaluru backup VPN up but failing its probe, since firewall changes this "
               "morning. Primary WAN links work everywhere; Singapore's backup is fine.", "protocol_fault", "p3", ["NYC", "BLR"],
               ["NYC backup VPN down", "BLR backup VPN up but probe fails", "Primary WAN fine", "Firewall changes this morning"], number=406)
    e.truth("Two changes on the hub CORE-FW-01: the New York pre-shared key was rotated on the hub only, so IKE authentication fails; and the "
            "static route for Bengaluru (10.30.0.0/16) via its tunnel was deleted, so the hub decrypts Bengaluru's traffic but has no route to "
            "send replies back through the tunnel (one-way).", ["CORE-FW-01"], ["BLR", "NYC"], ["PATH-BLR-INTERNET", "PATH-NYC-INTERNET"])


def s06_telemetry(e: Edit) -> None:
    for tunnel in e.t["ipsec"]["tunnels"]:
        pair = {tunnel["device_id"], tunnel["peer_device_id"]}
        if pair == {"NYC-RTR-01", "CORE-FW-01"}:
            hub = tunnel["device_id"] == "CORE-FW-01"
            tunnel.update(phase1="negotiating" if hub else "down", phase2_sas=0, last_change=e.at(-7.5))
        elif pair == {"BLR-RTR-01", "CORE-FW-01"}:
            if tunnel["device_id"] == "BLR-RTR-01":
                tunnel.update(encaps=5400, decaps=0, last_change=e.at(-30 + 12))
            else:
                tunnel.update(encaps=0, decaps=5400, last_change=e.at(-30 + 12))
    e.proto_event(-7, "ipsec", "IKE_AUTH_FAILED", "CORE-FW-01", "IKEv2 authentication with 198.51.100.10 failed: pre-shared key mismatch",
                  event_id="PE-S06-01", peer="NYC-RTR-01", count=24)
    for cert in e.t["tls"]["certificates"]:
        if cert["certificate_id"] == "CERT-RADIUS":
            cert["not_after"] = stamp(e.b.onset + timedelta(days=20))


# =====================================================================================================================
# SCN-07  Patch distribution moved into business hours saturates the metro link and WAN egress
# =====================================================================================================================

def s07_core(e: Edit) -> None:
    e.event(-1, "DC1-FW-01", "SESSION_SPIKE", "warning",
            "Session rate alert: 2,400 new tcp/445 sessions from 10.100.100.50 to 10.10.10.0/24, 10.20.10.0/24, 10.30.10.0/24", None, "EVT-S07-001")
    for interface in ("CORE-SW-01:Te1/0/4", "DC1-FW-01:ethernet1/1"):
        e.stats(interface, (5,), utilization_percent=98.1, out_drops=48200, in_drops=310)
        e.stats(interface, (15,), utilization_percent=97.4, out_drops=45100, in_drops=280)
    for interface in ("CORE-RTR-01:Gi0/0/2", "CORE-RTR-01:Gi0/0/3", "CORE-RTR-02:Gi0/0/2"):
        e.stats(interface, (5, 15), utilization_percent=93.2, out_drops=8800)
    e.event(2, "CORE-SW-01", "INTERFACE_DROPS", "warning", "%INTERFACE-4-DROPS: Te1/0/4 output drops increased by 48,200 in 60 s (queue full)",
            "CORE-SW-01:Te1/0/4", "EVT-S07-002")
    e.incident("Everything slow at every office since 09:00",
               "ERP and file shares are slow at all offices since about 09:00; calls sound fine. Last month the metro fibre had a fault.",
               "performance_degradation", "p2", ALL, ["ERP slow everywhere", "File shares slow", "Calls fine", "Metro fibre fault last month"], number=407)
    e.truth("The patch-distribution job on dc1-bkp-01 (10.100.100.50) was moved into business hours and pushes about 40 GB to the branch caches. "
            "It saturates the metro link between CORE-SW-01 and DC1-FW-01 and the core WAN egress; the drops are queue overflows, not errors. "
            "QoS keeps voice in the priority queue, so calls stay clean.", ["CORE-SW-01", "DC1-FW-01"], ["BLR", "NYC", "SIN"],
            ["PATH-BLR-APPLICATION", "PATH-NYC-APPLICATION", "PATH-SIN-APPLICATION"], ["LNK-CORE-DC1-METRO"])


def s07_telemetry(e: Edit) -> None:
    tcp(e, ALL, ("application",), retransmission_percent=(3.2, 4.8), rtt_ms=(230, 290))
    for sample in e.t["tcp"]["samples"]:
        if sample["service"] == "application" and e.after(sample):
            sample["bulk_retransmission_percent"] = round(sample["retransmission_percent"] * 1.1, 2)
            sample["small_retransmission_percent"] = round(sample["retransmission_percent"] * 0.9, 2)
    for sample in e.t["qos"]["samples"]:
        if sample["interface_id"] in ("CORE-RTR-01:Gi0/0/2", "CORE-RTR-01:Gi0/0/3", "CORE-RTR-02:Gi0/0/2") and e.after(sample):
            if sample["class_name"] == "BULK":
                sample.update(offered_kbps=round(sample["offered_kbps"] + 52000, 1), drop_percent=between(5.5, 7.5, "bulk", sample["sample_id"]))
            elif sample["class_name"] == "class-default":
                sample["drop_percent"] = between(1.5, 2.5, "def", sample["sample_id"])
    for counter in e.t["mtu"]["counters"]:
        if counter["device_id"] in ("CORE-RTR-01", "CORE-RTR-02") and e.after(counter):
            counter.update(fragments_created=whole(3000, 4200, counter["counter_id"]), reassembly_failures=whole(80, 140, "r", counter["counter_id"]))
    for site in ALL:
        for index, client in enumerate(e.lease_ips(site)[:4]):
            e.flow(-0.5 + index * 0.1, "10.100.100.50", client, 445, "tcp", 1_900_000_000, 2_400_000, "established", "DC1-FW-01", 1100)


# =====================================================================================================================
# SCN-08  A laptop sends IPv6 router advertisements on Singapore's user VLAN
# =====================================================================================================================

def s08_core(e: Edit) -> None:
    e.event(-14, "DC1-SRV-DNS-02", "SERVICE_HEALTH", "warning", "BIND: 3 SERVFAIL responses for updates.example.net (upstream lame delegation)",
            None, "EVT-S08-001")
    for index, site in enumerate(ALL):
        e.dns(f"DNS-Q-S08-{index + 1:02d}", -13 + index, e.lease_ip(site, 0), "10.100.100.11", "updates.example.net", "servfail", response_ms=412.0)
    for index, client in enumerate(e.lease_ips("SIN")[:3]):
        e.dns(f"DNS-Q-S08-{index + 11:02d}", 2 + index * 4, client, "10.100.100.10", "erp.corp.example.com", "noerror", ["10.100.100.40"], 171.2)
    e.incident("Singapore apps slow to connect; some sites fail",
               "Singapore users say applications take 20-30 seconds to connect and an IPv6-only portal fails; IPv4 works. DNS had errors earlier.",
               "protocol_fault", "p3", ["SIN"], ["Slow to connect", "IPv6-only portal fails", "IPv4 works", "DNS errors earlier"], number=408)
    e.truth("A laptop on Singapore's user VLAN 10 with internet connection sharing enabled sends IPv6 router advertisements. Dual-stack clients "
            "take it as their IPv6 default gateway and IPv6 is black-holed, so connections wait for IPv6 to time out. Most likely a "
            "misconfiguration rather than an attack. The earlier DNS SERVFAILs are an unrelated upstream problem.", ["SIN-SW-01"], ["SIN"],
            ["PATH-SIN-APPLICATION", "PATH-SIN-INTERNET"])


def s08_telemetry(e: Edit) -> None:
    laptop_mac = e.lease_mac("SIN", 7)
    for minute in (-1, 4, 9, 14):
        e.t["ipv6"]["adverts"].append({"ra_id": f"SIN|10|rogue@{e.at(minute)}", "timestamp": e.at(minute), "site_id": "SIN", "vlan_id": 10,
                                       "source_mac": laptop_mac, "source_link_local": "fe80::2a0:c9ff:fe14:1107", "router_device_id": None,
                                       "prefix": "2001:db8:abcd:1::/64", "router_lifetime": 1800})
    for probe in e.t["ipv6"]["probes"]:
        if probe["site_id"] == "SIN":
            probe["ipv6_ok"] = False


# =====================================================================================================================
# SCN-09  IGMP snooping querier disabled in New York: the video stream floods Wi-Fi
# =====================================================================================================================

def s09_core(e: Edit) -> None:
    e.command(-7, "NYC-SW-01", "netops", "no ip igmp snooping querier", "EVT-S09-001")
    e.event(2, "NYC-SW-01", "IGMP_QUERIER_LOST", "warning", "%IGMP_SNOOP-4-NO_QUERIER: No IGMP querier on vlan 10; group entries aging out", None,
            "EVT-S09-002")
    e.stats("NYC-SW-01:Gi1/0/24", (5, 15), utilization_percent=71.6)
    e.incident("New York Wi-Fi crawls during the all-hands video",
               "Since the all-hands stream started, Wi-Fi in New York is very slow and wired viewers lose the video every few minutes. A radar "
               "warning appeared on one access point.", "performance_degradation", "p3", ["NYC"],
               ["Wi-Fi very slow", "Video drops for wired viewers", "Radar warning on an AP"], number=409)
    e.truth("The IGMP snooping querier on NYC-SW-01 was disabled; snooping entries age out, the 3 Mbit/s all-hands stream floods every port in "
            "VLAN 10 including the AP uplinks, and the flooded multicast uses Wi-Fi airtime at low basic rates. The radar event is real but "
            "brief and not the cause.", ["NYC-SW-01"], ["NYC"], ["PATH-NYC-APPLICATION"])


def s09_telemetry(e: Edit) -> None:
    for group in e.t["multicast"]["groups"]:
        if group["device_id"] == "NYC-SW-01":
            group.update(querier_present=False, members=11)
    for sample in e.t["wireless"]["samples"]:
        if sample["ap_id"].startswith("NYC") and e.after(sample):
            key = sample["sample_id"]
            sample.update(channel_utilization=between(82, 88, "u", key), retry_percent=between(18, 24, "r", key),
                          non_wifi_interference=between(3, 5, "i", key), co_channel_aps=2, avg_snr_db=between(28, 31, "s", key, ndigits=1))
    e.proto_event(6, "wireless", "DFS_RADAR", "NYC-AP-01", "Radar detected on channel 52; radio moved to channel 36", event_id="PE-S09-01", count=1)


# =====================================================================================================================
# SCN-10  New TLS inspection CA not trusted by clients, an unregistered scanner and a workstation spraying passwords
# =====================================================================================================================

SCANNER = "10.100.100.61"


def s10_core(e: Edit) -> None:
    e.event(-12, "CORE-FW-01", "POLICY_CHANGE", "notice",
            "SSL decryption forward-proxy certificate changed to 'Corp Inspection CA 2027' by fwadmin (CHG-5311)", None, "EVT-S10-001")
    e.incident("Certificate errors on websites at every office; IDS also flagged a port sweep",
               "Users at all offices get certificate warnings on external websites since about 09:00; ERP is fine. The IDS also reported a port "
               "sweep from a data-centre address and failed logins from a Bengaluru desktop.", "security_threat", "p1", ALL,
               ["Certificate warnings on external sites", "ERP fine", "IDS port-sweep alert", "Failed logins from a BLR desktop"], number=410)
    e.truth("The TLS inspection re-sign certificate on CORE-FW-01 was replaced with 'Corp Inspection CA 2027', which was not distributed to "
            "clients, so every inspected HTTPS session fails with unknown_ca. Separately, 10.100.100.61 is IT's new vulnerability scanner "
            "(not yet on the allowlist) and a Bengaluru desktop is trying many passwords against other hosts; both need an analyst.",
            ["CORE-FW-01"], ["BLR", "NYC", "SIN"], ["PATH-BLR-INTERNET", "PATH-NYC-INTERNET", "PATH-SIN-INTERNET"])


def s10_telemetry(e: Edit) -> None:
    tls = e.t["tls"]
    for policy in tls["inspection"]:
        policy["resign_ca"] = "Corp Inspection CA 2027"
    for handshake in tls["handshakes"]:
        if handshake.get("via_inspection") and e.after(handshake):
            handshake.update(result="failure", alert="unknown_ca", tls_version="TLS1.3")
    targets = e.lease_ips("NYC")[:25] + e.lease_ips("SIN")[:20]
    for index, ip in enumerate(targets):
        for port in (22, 443, 445, 3389):
            e.flow(-9 + index * 0.08, SCANNER, ip, port, "tcp", 60, 0, "no_reply" if port != 443 else "rejected", "DC1-FW-01", 0.01)
    e.alert(-8.8, "DC1-FW-01", SCANNER, e.lease_ip("NYC", 0), "ET SCAN Nmap scripting engine user-agent detected", "recon", "low", "IDS-S10-01")
    sprayer = e.lease_ip("BLR", 3)
    hosts = [ip for ip in e.lease_ips("BLR") if ip != sprayer][:6]
    for index, host in enumerate(hosts):
        for account in ("administrator", "svc.backup"):
            e.auth(3 + index * 0.4, sprayer, f"blr-host-{host.split('.')[-1]}", account, "ntlm", "failure")
    e.alert(5, "BLR-SW-01", sprayer, hosts[0], "Multiple NTLM authentication failures from one host", "credential_access", "medium", "IDS-S10-02")


INCIDENT_SPECS: tuple[Spec, ...] = (
    Spec("SCN-01-NYC-WAN-FLAP-STORM", "Scenario 01 · New York circuit bouncing", "A degrading carrier circuit bounces five times: BGP flaps, OSPF "
         "externals re-flood, the backup VPN and video churn; an unrelated firewall change is a decoy.", "failure", 50, s01_core, s01_telemetry,
         ("wan", "bgp", "ospf", "ipsec", "tcp", "multicast", "mtu", "dns")),
    Spec("SCN-02-SIN-ORIGIN-ANOMALY", "Scenario 02 · Unexpected origin for Singapore users", "A lab AS behind New York announces a more-specific "
         "of Singapore's user subnet; half of Singapore loses return traffic.", "adversarial", 51, s02_core, s02_telemetry,
         ("bgp", "routing", "tcp", "dns", "wireless", "stp")),
    Spec("SCN-03-BLR-ROGUE-STP-ROOT", "Scenario 03 · Rogue switch takes the STP root", "A priority-0 switch on an unguarded port becomes root and "
         "keeps triggering topology changes; a DHCP pool warning is a decoy.", "failure", 52, s03_core, s03_telemetry, ("stp", "arp", "tcp", "dhcp")),
    Spec("SCN-04-NYC-VOICE-VLAN-DELETED", "Scenario 04 · Voice VLAN deleted, plus an address conflict", "VLAN 20 removed from the switch and trunk; an "
         "unrelated printer conflict; a DHCP CPU warning as a decoy.", "failure", 53, s04_core, s04_telemetry, ("vlan", "dhcp", "arp", "stp")),
    Spec("SCN-05-EDGE-NAT-RULE-SHADOW", "Scenario 05 · No-NAT rule shadows internet PAT", "A partner no-NAT rule above PAT takes the internet down "
         "everywhere; DNS errors look guilty but are a side effect.", "failure", 54, s05_core, s05_telemetry, ("nat", "firewall", "dns", "tcp", "tls")),
    Spec("SCN-06-HUB-VPN-PSK-AND-ROUTE", "Scenario 06 · Hub VPN changes break two tunnels", "Hub PSK rotated for New York only; Bengaluru's return route "
         "deleted (one-way tunnel); Singapore healthy for comparison.", "failure", 55, s06_core, s06_telemetry, ("ipsec", "firewall", "routing")),
    Spec("SCN-07-METRO-PATCH-CONGESTION", "Scenario 07 · Patch push saturates the metro link", "A mis-scheduled patch distribution congests the metro "
         "and WAN egress; QoS protects voice; an allowlisted bulk transfer and old fibre fault are decoys.", "edge", 56, s07_core, s07_telemetry,
         ("tcp", "qos", "mtu", "traffic", "lateral", "capacity")),
    Spec("SCN-08-SIN-ROGUE-IPV6-RA", "Scenario 08 · Laptop advertising IPv6 routes", "Rogue router advertisements black-hole IPv6 in Singapore; "
         "earlier DNS SERVFAILs are unrelated.", "adversarial", 57, s08_core, s08_telemetry, ("ipv6", "dns", "dhcp", "threats")),
    Spec("SCN-09-NYC-IGMP-QUERIER-WIFI", "Scenario 09 · Multicast flood slows Wi-Fi", "No IGMP querier: the video floods VLAN 10 and Wi-Fi airtime; "
         "a radar event is a decoy.", "failure", 58, s09_core, s09_telemetry, ("multicast", "wireless", "stp")),
    Spec("SCN-10-INSPECTION-CA-AND-SECURITY", "Scenario 10 · Inspection CA, scanner and password spraying", "An untrusted inspection CA breaks HTTPS "
         "everywhere while an unregistered scanner and a spraying desktop raise security indicators.", "adversarial", 59, s10_core, s10_telemetry,
         ("tls", "traffic", "lateral", "threats", "firewall")),
)
