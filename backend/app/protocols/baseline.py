"""Healthy synthetic protocol telemetry derived from the topology and a scenario's core dataset.

Values that the core dataset already fixes (BGP routes and sessions, OSPF neighbours, DHCP leases, interface MTUs) are
read from it, so the protocol layer never contradicts what the core tools report. Everything else is generated from
stable hashes, so a rerun reproduces the same telemetry byte for byte.
"""
import hashlib
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from app.network.models import DeviceType, NetworkTopology, ScenarioDataset

OFFSETS = (-15, -5, 5, 15)
BRANCHES = ("NYC", "SIN", "BLR")
SITE_CODE = {"NYC": 10, "SIN": 20, "BLR": 30}
BRANCH_PUBLIC = {"NYC": "198.51.100.10", "SIN": "198.51.100.20", "BLR": "198.51.100.30"}
EDGE_PUBLIC = "203.0.113.2"
APP_SERVER_IP = "10.100.100.40"
APP_SERVER = "DC1-SRV-APP-01"
AUTH_SERVER = "DC1-SRV-AUTH-01"
INTERNET_HOST = "198.51.100.15"
UPDATE_HOST = "198.51.100.80"
SCANNER_IP = "10.100.100.60"
BACKUP_IP = "10.100.100.50"
JUMP_HOST_IP = "10.255.0.200"
RP_ADDRESS = "10.255.0.1"
GROUP = "239.10.1.1"
CONTROLLER = "CORE-WLC-01"
ORIGINS = (("10.10.0.0/16", 65010), ("10.20.0.0/16", 65020))  # branch-originated address space; everything else starts in AS65000
PROPOSAL = {"encryption": "aes256-gcm", "integrity": "sha384", "dh_group": 20, "lifetime_seconds": 28800}
RTT = {"NYC": 72.0, "SIN": 168.0, "BLR": 141.0}
QOS_CLASSES = [
    {"name": "VOICE", "dscp": [46], "priority": True, "bandwidth_percent": 20},
    {"name": "VIDEO", "dscp": [34], "bandwidth_percent": 15},
    {"name": "SIGNALLING", "dscp": [24], "bandwidth_percent": 5},
    {"name": "BUSINESS", "dscp": [26], "bandwidth_percent": 25},
    {"name": "BULK", "dscp": [10], "bandwidth_percent": 10},
    {"name": "SCAVENGER", "dscp": [8], "bandwidth_percent": 5, "drops_expected": True},
    {"name": "class-default", "dscp": [0], "bandwidth_percent": 20, "drops_expected": True},
]
CLASS_LOAD = {"VOICE": (700, 1400, 0, 0), "VIDEO": (1500, 3000, 0, 0.05), "SIGNALLING": (40, 90, 0, 0),
              "BUSINESS": (6000, 12000, 0, 0.05), "BULK": (3000, 9000, 0, 0.2), "SCAVENGER": (500, 2500, 0.4, 2.5),
              "class-default": (4000, 9000, 0, 0.3)}
WAN_EDGES = ["NYC-RTR-01:Gi0/0/0", "SIN-RTR-01:Gi0/0/0", "BLR-RTR-01:Gi0/0/0", "CORE-RTR-01:Gi0/0/2", "CORE-RTR-01:Gi0/0/3",
             "CORE-RTR-02:Gi0/0/2"]
# The multicast distribution tree from the DC source to the three branches: device -> (incoming, outgoing interfaces).
TREE = {
    "DC1-SW-01": ("DC1-SW-01:Vlan100", ["DC1-SW-01:Te1/1/1"]),
    "DC1-FW-01": ("DC1-FW-01:ethernet1/2", ["DC1-FW-01:ethernet1/1"]),
    "CORE-SW-01": ("CORE-SW-01:Te1/0/4", ["CORE-SW-01:Te1/0/1", "CORE-SW-01:Te1/0/2"]),
    "CORE-RTR-01": ("CORE-RTR-01:Te0/0/0", ["CORE-RTR-01:Gi0/0/2", "CORE-RTR-01:Gi0/0/3"]),
    "CORE-RTR-02": ("CORE-RTR-02:Te0/0/0", ["CORE-RTR-02:Gi0/0/2"]),
    "NYC-RTR-01": ("NYC-RTR-01:Gi0/0/0", ["NYC-RTR-01:Gi0/0/1.10"]),
    "SIN-RTR-01": ("SIN-RTR-01:Gi0/0/0", ["SIN-RTR-01:Gi0/0/1.10"]),
    "BLR-RTR-01": ("BLR-RTR-01:Gi0/0/0", ["BLR-RTR-01:Gi0/0/1.10"]),
}
PIM_LINKS = ["LNK-DC1-FW01-SW01", "LNK-CORE-DC1-METRO", "LNK-CORE-RTR01-SW01", "LNK-CORE-RTR02-SW01", "LNK-CORE-RTR01-RTR02",
             "LNK-WAN-NYC", "LNK-WAN-SIN", "LNK-WAN-BLR"]
V6_LINKS = {"LNK-WAN-NYC": 1, "LNK-WAN-SIN": 2, "LNK-WAN-BLR": 3, "LNK-CORE-RTR01-SW01": 11, "LNK-CORE-RTR02-SW01": 12,
            "LNK-CORE-RTR01-RTR02": 13}


def digest(*parts: Any) -> int:
    return int.from_bytes(hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()[:8], "big")


def frac(*parts: Any) -> float:
    return digest(*parts) / 2 ** 64


def between(low: float, high: float, *parts: Any, ndigits: int = 2) -> float:
    return round(low + (high - low) * frac(*parts), ndigits)


def whole(low: int, high: int, *parts: Any) -> int:
    return low + digest(*parts) % (high - low + 1)


def mac(*parts: Any) -> str:
    raw = digest("mac", *parts).to_bytes(8, "big")[:5]
    return "02:" + ":".join(f"{b:02x}" for b in raw)


def fingerprint(*parts: Any) -> str:
    return f"{digest('fp', *parts):016x}"


def checksum(*parts: Any) -> str:
    return f"0x{digest('ck', *parts) % 65536:04x}"


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class Builder:
    """Builds the healthy telemetry for one dataset; scenario mutators edit the resulting plain dictionary."""

    def __init__(self, topology: NetworkTopology, dataset: ScenarioDataset) -> None:
        self.topology, self.dataset = topology, dataset
        info = dataset.scenario
        self.start, self.onset, self.end = info.window_start, info.onset_at, info.window_end
        self.devices = {d.device_id: d for d in topology.devices}
        self.interfaces = {i.interface_id: i for i in topology.interfaces}
        self.links = {link.link_id: link for link in topology.links}
        self.sid = info.scenario_id

    def at(self, minutes: float) -> str:
        return stamp(self.onset + timedelta(minutes=minutes))

    def times(self) -> list[tuple[int, str]]:
        return [(offset, self.at(offset)) for offset in OFFSETS]

    def leases(self, site: str, vlan: int = 10) -> list[Any]:
        pools = {p.pool_id: p for p in self.dataset.dhcp.pools if p.site_id == site and p.vlan_id == vlan}
        return [lease for lease in self.dataset.dhcp.leases if lease.pool_id in pools and lease.state.value == "active"]

    def build(self) -> dict[str, Any]:
        collected = stamp(self.end - timedelta(minutes=1))
        return {
            "scenario_id": self.sid, "synthetic": True,
            "description": f"Synthetic protocol and security telemetry for {self.sid}, generated locally; not from real devices.",
            "events": [], "bgp": self.bgp(collected), "ospf": self.ospf(collected), "stp": self.stp(collected),
            "arp": self.arp(collected), "vlan": self.trunks(collected), "nat": self.nat(collected), "ipsec": self.ipsec(collected),
            "tcp": self.tcp(collected), "mtu": self.mtu(collected), "qos": self.qos(collected), "ipv6": self.ipv6(collected),
            "wireless": self.wireless(collected), "multicast": self.multicast(collected), "tls": self.tls(collected),
            "security": self.security(collected),
        }

    # ---------- routing ----------

    def bgp(self, collected: str) -> dict[str, Any]:
        neighbours = self.dataset.routing.bgp_neighbors
        sessions = [{"session_id": f"{n.device_id}>{n.neighbor_device_id}", "device_id": n.device_id, "peer_device_id": n.neighbor_device_id,
                     "state": n.state.value, "last_change": stamp(n.last_state_change)} for n in neighbours]
        by_hop = {(n.device_id, str(n.neighbor_ip)): n for n in neighbours}
        routes = []
        for table in self.dataset.routing.routing_tables:
            for route in table.routes:
                if route.protocol.value != "bgp":
                    continue
                neighbour = by_hop.get((table.device_id, str(route.next_hop)))
                if neighbour is None:
                    continue
                # A route re-advertised by the core keeps the AS that originated it at the end of the path.
                origin = next((asn for prefix, asn in ORIGINS if route.prefix.subnet_of(IPv4Network(prefix))), neighbour.remote_asn)
                path = [neighbour.remote_asn] if neighbour.remote_asn != neighbour.local_asn else []
                if path and origin != path[-1]:
                    path.append(origin)
                routes.append({"route_id": f"{table.device_id}|{route.prefix}|{neighbour.neighbor_device_id}", "device_id": table.device_id,
                               "prefix": str(route.prefix), "next_hop": str(route.next_hop), "peer_device_id": neighbour.neighbor_device_id,
                               "as_path": path, "origin_asn": path[-1] if path else origin, "learned_at": stamp(neighbour.last_state_change)})
        for site, device in (("NYC", "NYC-RTR-01"), ("SIN", "SIN-RTR-01")):
            if device not in {n.device_id for n in neighbours}:
                continue
            for vlan in (v for v in self.topology.vlans if v.site_id == site):
                routes.append({"route_id": f"{device}|{vlan.subnet}|local", "device_id": device, "prefix": str(vlan.subnet),
                               "next_hop": "0.0.0.0", "as_path": [], "origin_asn": self.devices[device].bgp_asn,
                               "learned_at": stamp(self.start - timedelta(days=40))})
        authorizations = [
            {"prefix": "10.10.0.0/16", "origin_asn": 65010, "max_length": 24}, {"prefix": "10.20.0.0/16", "origin_asn": 65020, "max_length": 24},
            {"prefix": "10.30.0.0/16", "origin_asn": 65000, "max_length": 24}, {"prefix": "10.100.0.0/16", "origin_asn": 65000, "max_length": 24},
            {"prefix": "0.0.0.0/0", "origin_asn": 65000, "max_length": 0}, {"prefix": "172.16.0.0/16", "origin_asn": 65000, "max_length": 30},
        ]
        return {"collected_from": sorted({n.device_id for n in neighbours}), "collected_at": collected, "routes": routes, "updates": [],
                "authorizations": authorizations, "sessions": sessions}

    def ospf_routers(self) -> list[str]:
        return sorted({n.device_id for n in self.dataset.routing.ospf_neighbors} | {n.neighbor_device_id for n in self.dataset.routing.ospf_neighbors}
                      | {"CORE-RTR-01", "CORE-RTR-02", "CORE-SW-01", "BLR-RTR-01"})

    def ospf(self, collected: str) -> dict[str, Any]:
        routers = self.ospf_routers()
        rid = {d: str(self.devices[d].router_id) for d in routers}
        links = {d: len([n for n in self.dataset.routing.ospf_neighbors if n.device_id == d]) for d in routers}
        externals = [("CORE-SW-01", "0.0.0.0"), ("CORE-SW-01", "10.100.100.0")]
        externals += [("CORE-RTR-01", f"10.{c}.{v}.0") for c in (10, 20) for v in (10, 20, 99)]
        lsas = []
        for observer in routers:
            for router in routers:
                seq = 0x80000000 + whole(20, 60, "seq", router)
                lsas.append({"lsa_id": f"{observer}|router|{rid[router]}", "observed_by": observer, "area": "0", "lsa_type": "router",
                             "link_state_id": rid[router], "advertising_router": rid[router], "sequence": seq,
                             "age_seconds": whole(80, 1700, "age", router) + whole(0, 2, observer), "checksum": checksum(router, seq),
                             "link_count": links[router] + 2})
            for router, network in externals:
                seq = 0x80000000 + whole(5, 30, "seq", network)
                lsas.append({"lsa_id": f"{observer}|external|{network}", "observed_by": observer, "area": "0", "lsa_type": "external",
                             "link_state_id": network, "advertising_router": rid[router], "sequence": seq,
                             "age_seconds": whole(80, 1700, "age", network) + whole(0, 2, observer), "checksum": checksum(network, seq)})
        return {"collected_from": routers, "collected_at": collected, "lsas": lsas, "updates": [], "router_ids": rid}

    # ---------- switching ----------

    def switches(self) -> list[str]:
        return [d.device_id for d in self.topology.devices if d.device_type == DeviceType.SWITCH]

    def site_vlans(self, site: str) -> list[int]:
        vlans = [v.vlan_id for v in self.topology.vlans if v.site_id == site]
        return vlans or [1]

    def stp(self, collected: str) -> dict[str, Any]:
        expected, vlans, ports = [], [], []
        for switch in self.switches():
            site = self.devices[switch].site_id
            for vlan in self.site_vlans(site):
                expected.append({"site_id": site, "vlan_id": vlan, "device_id": switch})
                vlans.append({"state_id": f"{switch}|{vlan}", "device_id": switch, "vlan_id": vlan, "bridge_mac": mac("bridge", switch),
                              "bridge_priority": 24576, "root_mac": mac("bridge", switch), "root_priority": 24576, "root_port": None,
                              "topology_changes": whole(2, 9, "tc", switch, vlan),
                              "last_topology_change": stamp(self.start - timedelta(days=whole(2, 30, "lasttc", switch), hours=whole(0, 20, switch))),
                              "tc_source_port": None})
                members = [i for i in self.topology.interfaces if i.device_id == switch and i.mode.value in ("access", "trunk") and vlan in i.vlan_ids]
                for interface in members:
                    port = interface.interface_id.split(":", 1)[1]
                    edge = interface.mode.value == "access"
                    ports.append({"port_id": f"{switch}|{port}|{vlan}", "device_id": switch, "port": port, "vlan_id": vlan, "role": "designated",
                                  "state": "forwarding", "edge": edge, "bpdu_guard": edge})
                if site in BRANCHES and vlan == 10:
                    for port in ("Gi1/0/10", "Gi1/0/11"):
                        ports.append({"port_id": f"{switch}|{port}|{vlan}", "device_id": switch, "port": port, "vlan_id": vlan,
                                      "role": "designated", "state": "forwarding", "edge": True, "bpdu_guard": True})
        return {"collected_from": self.switches(), "collected_at": collected, "expected_roots": expected, "vlans": vlans, "ports": ports}

    def gateway(self, site: str, vlan: int) -> tuple[str, str]:
        segment = next(v for v in self.topology.vlans if v.site_id == site and v.vlan_id == vlan)
        device = self.interfaces[segment.gateway_interface_id].device_id
        return str(segment.gateway), device

    def arp(self, collected: str) -> dict[str, Any]:
        gateways, entries, static = [], [], []
        for segment in self.topology.vlans:
            ip, device = self.gateway(segment.site_id, segment.vlan_id)
            gateways.append({"site_id": segment.site_id, "vlan_id": segment.vlan_id, "ip": ip, "mac": mac("gw", device), "device_id": device})
        for site in BRANCHES:
            ip, device = self.gateway(site, 10)
            port = next(v.gateway_interface_id for v in self.topology.vlans if v.site_id == site and v.vlan_id == 10).split(":")[1]
            for lease in self.leases(site):
                entries.append({"entry_id": f"{device}|{lease.ip_address}", "device_id": device, "vlan_id": 10, "ip": str(lease.ip_address),
                                "mac": lease.mac_address, "port": port, "first_seen": stamp(max(lease.lease_start, self.start - timedelta(hours=8))),
                                "last_seen": self.at(whole(8, 18, "seen", lease.ip_address))})
            printer = f"10.{SITE_CODE[site]}.10.20"
            static.append({"ip": printer, "mac": mac("printer", site), "hostname": f"{site.lower()}-prn-01"})
            entries.append({"entry_id": f"{device}|{printer}", "device_id": device, "vlan_id": 10, "ip": printer, "mac": mac("printer", site),
                            "port": port, "first_seen": stamp(self.start - timedelta(days=3)), "last_seen": self.at(10)})
        for server in (d for d in self.topology.devices if d.device_type == DeviceType.SERVER):
            entries.append({"entry_id": f"DC1-SW-01|{server.management_ip}", "device_id": "DC1-SW-01", "vlan_id": 100, "ip": str(server.management_ip),
                            "mac": mac("server", server.device_id), "port": "Vlan100", "first_seen": stamp(self.start - timedelta(days=12)),
                            "last_seen": self.at(12)})
        for ip, name in ((SCANNER_IP, "dc1-vscan-01"), (BACKUP_IP, "dc1-bkp-01")):
            static.append({"ip": ip, "mac": mac("host", ip), "hostname": name})
            entries.append({"entry_id": f"DC1-SW-01|{ip}", "device_id": "DC1-SW-01", "vlan_id": 100, "ip": ip, "mac": mac("host", ip), "port": "Vlan100",
                            "first_seen": stamp(self.start - timedelta(days=12)), "last_seen": self.at(12)})
        collected_from = sorted({g["device_id"] for g in gateways} | {f"{s}-SW-01" for s in BRANCHES})
        return {"collected_from": collected_from, "collected_at": collected, "entries": entries, "gateways": gateways, "static_hosts": static}

    def trunks(self, collected: str) -> dict[str, Any]:
        ports, databases = [], []
        for site in BRANCHES:
            link = self.links[f"LNK-{site}-RTR01-SW01"]
            vlans = self.site_vlans(site)
            ports.append({"port_id": link.a_interface_id, "device_id": f"{site}-RTR-01", "interface_id": link.a_interface_id, "link_id": link.link_id,
                          "mode": "dot1q_subinterfaces", "native_vlan": 1, "allowed_vlans": vlans, "dtp": "nonegotiate"})
            ports.append({"port_id": link.b_interface_id, "device_id": f"{site}-SW-01", "interface_id": link.b_interface_id, "link_id": link.link_id,
                          "mode": "trunk", "native_vlan": 1, "allowed_vlans": vlans, "dtp": "nonegotiate"})
            databases.append({"device_id": f"{site}-SW-01", "vlans": [1, *vlans]})
        databases.append({"device_id": "DC1-SW-01", "vlans": [1, 100]})
        collected_from = sorted([f"{s}-RTR-01" for s in BRANCHES] + [f"{s}-SW-01" for s in BRANCHES] + ["DC1-SW-01"])
        return {"collected_from": collected_from, "collected_at": collected, "ports": ports, "databases": databases}

    # ---------- edge services ----------

    def nat(self, collected: str) -> dict[str, Any]:
        capacity = 4 * 64512
        samples, talkers = [], []
        for offset, at in self.times():
            samples.append({"sample_id": f"PAT-INTERNET@{at}", "timestamp": at, "pool_id": "PAT-INTERNET",
                            "active_translations": int(capacity * between(0.22, 0.38, "nat", offset)), "allocation_failures": 0})
            for rank, lease in enumerate(self.leases("NYC")[:2] + self.leases("SIN")[:1]):
                talkers.append({"talker_id": f"PAT-INTERNET|{lease.ip_address}@{at}", "timestamp": at, "pool_id": "PAT-INTERNET",
                                "inside_ip": str(lease.ip_address), "translations": whole(250, 900, "tt", lease.ip_address, offset),
                                "destinations": whole(15, 60, "td", lease.ip_address, offset)})
        site_networks = {site: [f"10.{SITE_CODE[site]}.10.0/24"] for site in BRANCHES}
        return {"collected_from": ["CORE-FW-01"], "collected_at": collected,
                "pools": [{"pool_id": "PAT-INTERNET", "device_id": "CORE-FW-01", "kind": "pat", "public_addresses": 4, "ports_per_address": 64512}],
                "rules": [{"rule_id": "NAT-0100", "device_id": "CORE-FW-01", "order": 100, "source": "10.0.0.0/8", "pool_id": "PAT-INTERNET",
                           "enabled": True, "last_modified": "2026-01-15T10:00:00Z"}],
                "samples": samples, "top_talkers": talkers, "site_networks": site_networks}

    def ipsec(self, collected: str) -> dict[str, Any]:
        tunnels = []
        for site in BRANCHES:
            local = [f"10.{SITE_CODE[site]}.0.0/16"]
            remote = ["10.100.100.0/24"]
            common = {"role": "backup", "ike_version": 2, "auth": "psk", "local_proposal": dict(PROPOSAL), "peer_proposal": dict(PROPOSAL),
                      "phase1": "up", "phase2_sas": 2, "errors": 0, "dpd_timeouts": 0, "last_change": stamp(self.start - timedelta(days=whole(3, 20, site)))}
            tunnels.append({**common, "tunnel_id": f"TUN-{site}-BACKUP", "device_id": f"{site}-RTR-01", "peer_device_id": "CORE-FW-01",
                            "local_ip": BRANCH_PUBLIC[site], "peer_ip": EDGE_PUBLIC, "local_selectors": local, "peer_selectors": remote,
                            "encaps": whole(900, 1400, "enc", site), "decaps": whole(880, 1380, "dec", site),
                            "underlay_interface_id": f"{site}-RTR-01:Gi0/0/0"})
            tunnels.append({**common, "tunnel_id": f"TUN-{site}-BACKUP-HUB", "device_id": "CORE-FW-01", "peer_device_id": f"{site}-RTR-01",
                            "local_ip": EDGE_PUBLIC, "peer_ip": BRANCH_PUBLIC[site], "local_selectors": remote, "peer_selectors": local,
                            "encaps": whole(880, 1380, "dec", site), "decaps": whole(900, 1400, "enc", site), "underlay_interface_id": "CORE-FW-01:ethernet1/1"})
        return {"collected_from": sorted([f"{s}-RTR-01" for s in BRANCHES] + ["CORE-FW-01"]), "collected_at": collected, "tunnels": tunnels}

    # ---------- transport ----------

    def tcp(self, collected: str) -> dict[str, Any]:
        samples = []
        for site in BRANCHES:
            for service, path, server, extra in (("application", f"PATH-{site}-APPLICATION", APP_SERVER, 0.0), ("internet", f"PATH-{site}-INTERNET", None, 9.0)):
                for offset, at in self.times():
                    retrans = between(0.1, 0.6, "rt", site, service, offset)
                    samples.append({"sample_id": f"{path}@{at}", "timestamp": at, "site_id": site, "service": service, "path_id": path,
                                    "server_device_id": server, "flows": whole(120, 400, "flows", site, service, offset),
                                    "retransmission_percent": retrans, "bulk_retransmission_percent": round(retrans * 1.1, 2),
                                    "small_retransmission_percent": round(retrans * 0.9, 2), "rtt_ms": round(RTT[site] + extra + between(-4, 4, site, offset), 1),
                                    "syn_retry_percent": between(0, 0.3, "syn", site, service, offset), "zero_window_events": whole(0, 2, "zw", site, offset),
                                    "resets": whole(1, 6, "rst", site, service, offset)})
        return {"collected_from": ["CORE-FW-01", "DC1-FW-01"], "collected_at": collected, "samples": samples}

    def mtu(self, collected: str) -> dict[str, Any]:
        interfaces = [{"interface_id": i.interface_id, "ip_mtu": i.mtu} for i in self.topology.interfaces
                      if i.ip_address is not None and self.devices[i.device_id].device_type in (DeviceType.ROUTER, DeviceType.FIREWALL)]
        probes, counters = [], []
        for site in BRANCHES:
            for size in (1500, 1400, 1200):
                at = self.at(-10 + (size % 7))
                probes.append({"probe_id": f"{site}-RTR-01>{APP_SERVER_IP}/{size}@{at}", "timestamp": at, "source_device_id": f"{site}-RTR-01",
                               "destination_ip": APP_SERVER_IP, "path_id": f"PATH-{site}-APPLICATION", "size": size, "df": True, "result": "ok"})
        for device in ("NYC-RTR-01", "SIN-RTR-01", "BLR-RTR-01", "CORE-RTR-01", "CORE-RTR-02"):
            for offset, at in self.times():
                counters.append({"counter_id": f"{device}@{at}", "timestamp": at, "device_id": device, "fragments_created": whole(0, 12, "frag", device, offset),
                                 "reassembly_failures": 0, "frag_needed_sent": 0})
        return {"collected_from": ["BLR-RTR-01", "CORE-RTR-01", "CORE-RTR-02", "NYC-RTR-01", "SIN-RTR-01"], "collected_at": collected,
                "probes": probes, "interfaces": interfaces, "counters": counters, "icmp_filtered_on": []}

    def qos(self, collected: str) -> dict[str, Any]:
        expected = [{"interface_id": i, "direction": "output", "name": "WAN-EDGE-QOS"} for i in WAN_EDGES]
        policies = [{"policy_id": f"{i}|output", "interface_id": i, "direction": "output", "name": "WAN-EDGE-QOS", "classes": QOS_CLASSES, "applied": True}
                    for i in WAN_EDGES]
        samples, markings = [], []
        for interface in WAN_EDGES:
            for offset, at in self.times():
                for name, (low, high, drop_low, drop_high) in CLASS_LOAD.items():
                    samples.append({"sample_id": f"{interface}|{name}@{at}", "timestamp": at, "interface_id": interface, "class_name": name,
                                    "offered_kbps": between(low, high, "q", interface, name, offset, ndigits=1),
                                    "drop_percent": between(drop_low, drop_high, "qd", interface, name, offset), "queue_depth": whole(0, 12, "qq", interface, name, offset)})
        for site in BRANCHES:
            core_in = {"NYC": "CORE-RTR-01:Gi0/0/2", "SIN": "CORE-RTR-01:Gi0/0/3", "BLR": "CORE-RTR-02:Gi0/0/2"}[site]
            at = self.at(6)
            for interface, direction in ((f"{site}-SW-01:Gi1/0/24", "output"), (f"{site}-RTR-01:Gi0/0/0", "output"), (core_in, "input")):
                for traffic, dscp in (("voice", 46), ("business", 26)):
                    markings.append({"observation_id": f"{interface}|{direction}|{traffic}@{at}", "timestamp": at, "interface_id": interface,
                                     "direction": direction, "traffic": traffic, "expected_dscp": dscp, "observed_dscp": dscp, "share_percent": 100})
        return {"collected_from": sorted({i.split(":")[0] for i in WAN_EDGES} | {f"{s}-SW-01" for s in BRANCHES}), "collected_at": collected,
                "expected": expected, "policies": policies, "samples": samples, "markings": markings}

    def ipv6(self, collected: str) -> dict[str, Any]:
        prefixes, addresses, routes, adverts, probes = [], [], [], [], []
        for site, code in (("NYC", "10"), ("SIN", "20"), ("BLR", "30")):
            for vlan in (10, 20):
                prefix = f"2001:db8:{code}:{vlan}::/64"
                prefixes.append({"site_id": site, "vlan_id": vlan, "prefix": prefix})
                interface = f"{site}-RTR-01:Gi0/0/1.{vlan}"
                link_local = f"fe80::{digest('ll', interface) % 65535:x}"
                addresses.append({"interface_id": interface, "address": f"2001:db8:{code}:{vlan}::1/64", "link_local": link_local})
                routes.append({"route_id": f"{site}-RTR-01|{prefix}", "device_id": f"{site}-RTR-01", "prefix": prefix, "protocol": "connected", "interface_id": interface})
                for minute in (-12, 3):
                    adverts.append({"ra_id": f"{site}|{vlan}@{self.at(minute)}", "timestamp": self.at(minute), "site_id": site, "vlan_id": vlan,
                                    "source_mac": mac("gw", f"{site}-RTR-01"), "source_link_local": link_local, "router_device_id": f"{site}-RTR-01",
                                    "prefix": prefix, "router_lifetime": 1800})
            for service in ("application", "internet", "dns"):
                probes.append({"probe_id": f"{site}|{service}@{self.at(5)}", "timestamp": self.at(5), "site_id": site, "service": service,
                               "ipv4_ok": True, "ipv6_ok": True})
        prefixes.append({"site_id": "DC1", "vlan_id": 100, "prefix": "2001:db8:100:100::/64"})
        link_local = {}
        for link_id, number in V6_LINKS.items():
            link = self.links[link_id]
            for side, interface in ((1, link.a_interface_id), (2, link.b_interface_id)):
                link_local[interface] = f"fe80::{digest('ll', interface) % 65535:x}"
                addresses.append({"interface_id": interface, "address": f"2001:db8:ffff:{number}::{side}/64", "link_local": link_local[interface]})
        wan = {"NYC": ("LNK-WAN-NYC", "bgp"), "SIN": ("LNK-WAN-SIN", "bgp"), "BLR": ("LNK-WAN-BLR", "ospfv3")}
        for site, (link_id, protocol) in wan.items():
            link = self.links[link_id]
            core, branch = link.a_interface_id, link.b_interface_id
            routes.append({"route_id": f"{site}-RTR-01|::/0", "device_id": f"{site}-RTR-01", "prefix": "::/0", "protocol": protocol,
                           "next_hop": link_local[core], "interface_id": branch})
            for vlan in (10, 20):
                prefix = f"2001:db8:{SITE_CODE[site]}:{vlan}::/64"
                routes.append({"route_id": f"{core.split(':')[0]}|{prefix}", "device_id": core.split(":")[0], "prefix": prefix, "protocol": protocol,
                               "next_hop": link_local[branch], "interface_id": core})
        for device, interface, peer in (("CORE-RTR-01", "CORE-RTR-01:Te0/0/0", "CORE-SW-01:Te1/0/1"), ("CORE-RTR-02", "CORE-RTR-02:Te0/0/0", "CORE-SW-01:Te1/0/2")):
            routes.append({"route_id": f"{device}|2001:db8:100:100::/64", "device_id": device, "prefix": "2001:db8:100:100::/64", "protocol": "ospfv3",
                           "next_hop": link_local[peer], "interface_id": interface})
        neighbours = [{"neighbor_id": f"{n.device_id}>{n.neighbor_device_id}", "device_id": n.device_id, "interface_id": n.interface_id,
                       "neighbor_device_id": n.neighbor_device_id, "state": "full", "last_change": stamp(n.last_state_change)}
                      for n in self.dataset.routing.ospf_neighbors if n.state.value == "full"]
        routers = sorted({d.device_id for d in self.topology.devices if d.device_type == DeviceType.ROUTER})
        return {"collected_from": routers, "collected_at": collected, "addresses": addresses, "routes": routes, "neighbors": neighbours,
                "adverts": adverts, "site_prefixes": prefixes, "probes": probes}

    # ---------- wireless ----------

    def wireless(self, collected: str) -> dict[str, Any]:
        aps, samples = [], []
        for site in BRANCHES:
            for index, port in ((1, "Gi1/0/10"), (2, "Gi1/0/11")):
                ap = f"{site}-AP-0{index}"
                aps.append({"ap_id": ap, "site_id": site, "controller_id": CONTROLLER, "switch_device_id": f"{site}-SW-01", "switch_port": port})
                for band, channel in (("2.4GHz", (1, 6)[index - 1]), ("5GHz", (36, 44)[index - 1])):
                    for offset, at in self.times():
                        samples.append({"sample_id": f"{ap}|{band}@{at}", "timestamp": at, "ap_id": ap, "band": band, "channel": channel,
                                        "channel_utilization": between(18, 42, "cu", ap, band, offset), "non_wifi_interference": between(1, 6, "ni", ap, band, offset),
                                        "noise_floor_dbm": between(-96, -92, "nf", ap, band, offset, ndigits=1), "retry_percent": between(4, 10, "rp", ap, band, offset),
                                        "clients": whole(8, 28, "cl", ap, band, offset), "avg_rssi_dbm": between(-63, -55, "rs", ap, band, offset, ndigits=1),
                                        "avg_snr_db": between(28, 36, "sn", ap, band, offset, ndigits=1), "co_channel_aps": whole(0, 1, "cc", ap, band)})
        return {"collected_from": [CONTROLLER], "collected_at": collected,
                "controllers": [{"controller_id": CONTROLLER, "platform": "Cisco Catalyst 9800-40", "synthetic": True}],
                "access_points": aps, "samples": samples, "rogues": [], "corporate_ssids": ["CORP-WIFI", "CORP-VOICE"]}

    # ---------- multicast ----------

    def multicast(self, collected: str) -> dict[str, Any]:
        neighbours = []
        for link_id in PIM_LINKS:
            link = self.links[link_id]
            for interface, peer in ((link.a_interface_id, link.b_device_id), (link.b_interface_id, link.a_device_id)):
                device = interface.split(":")[0]
                neighbours.append({"neighbor_id": f"{device}>{peer}", "device_id": device, "interface_id": interface, "neighbor_device_id": peer,
                                   "state": "up", "last_change": stamp(self.start - timedelta(days=whole(5, 40, "pim", device, peer)))})
        routers = sorted(TREE)
        mappings = [{"mapping_id": f"{d}|239.0.0.0/8", "device_id": d, "group_range": "239.0.0.0/8", "rp_address": RP_ADDRESS} for d in routers]
        mroutes = [{"mroute_id": f"{d}|{APP_SERVER_IP}|{GROUP}", "device_id": d, "source": APP_SERVER_IP, "group": GROUP,
                    "incoming_interface_id": incoming, "outgoing_interface_ids": outgoing, "packets_per_second": between(280, 320, "pps", d),
                    "rpf_failures": 0} for d, (incoming, outgoing) in TREE.items()]
        groups = [{"group_id": f"{site}-SW-01|10|{GROUP}", "device_id": f"{site}-SW-01", "vlan_id": 10, "group": GROUP,
                   "members": whole(6, 14, "igmp", site), "querier_present": True} for site in BRANCHES]
        return {"collected_from": routers, "collected_at": collected, "expected_rp": RP_ADDRESS, "group_range": "239.0.0.0/8",
                "streams": [{"stream_id": "MCAST-ALLHANDS", "name": "All-hands video", "source_ip": APP_SERVER_IP, "source_device_id": APP_SERVER,
                             "group": GROUP, "receiver_sites": list(BRANCHES)}],
                "neighbors": neighbours, "rp_mappings": mappings, "mroutes": mroutes, "groups": groups}

    # ---------- TLS ----------

    def tls(self, collected: str) -> dict[str, Any]:
        erp = {"certificate_id": "CERT-ERP", "service": "erp", "device_id": APP_SERVER, "common_name": "erp.corp.example.com",
               "sans": ["erp.corp.example.com", "erp"], "issuer": "Corp Issuing CA 01", "not_before": stamp(self.start - timedelta(days=200)),
               "not_after": stamp(self.start + timedelta(days=165)), "key_bits": 2048, "chain_complete": True, "fingerprint": fingerprint("erp")}
        radius = {"certificate_id": "CERT-RADIUS", "service": "radius", "device_id": AUTH_SERVER, "common_name": "radius.corp.example.com",
                  "sans": ["radius.corp.example.com"], "issuer": "Corp Issuing CA 01", "not_before": stamp(self.start - timedelta(days=90)),
                  "not_after": stamp(self.start + timedelta(days=275)), "key_bits": 2048, "chain_complete": True, "fingerprint": fingerprint("radius")}
        handshakes = []
        for site in BRANCHES:
            clients = self.leases(site)[:2]
            for offset, at in self.times():
                for lease in clients:
                    handshakes.append({"handshake_id": f"{lease.ip_address}>erp@{at}", "timestamp": at, "client_site_id": site, "client_ip": str(lease.ip_address),
                                       "server_ip": APP_SERVER_IP, "sni": "erp.corp.example.com", "result": "success", "tls_version": "TLS1.3",
                                       "presented_fingerprint": fingerprint("erp")})
                lease = clients[0]
                handshakes.append({"handshake_id": f"{lease.ip_address}>web@{at}", "timestamp": at, "client_site_id": site, "client_ip": str(lease.ip_address),
                                   "server_ip": INTERNET_HOST, "sni": "www.example.com", "result": "success", "tls_version": "TLS1.3",
                                   "presented_fingerprint": fingerprint("inspection", "www.example.com"), "via_inspection": True})
        return {"collected_from": ["CORE-FW-01", "DC1-FW-01"], "collected_at": collected, "certificates": [erp, radius], "handshakes": handshakes,
                "inspection": [{"device_id": "CORE-FW-01", "decrypts": True, "resign_ca": "Corp Inspection CA", "sites": list(BRANCHES)}],
                "trusted_cas": ["Corp Root CA", "Corp Issuing CA 01", "Corp Inspection CA"]}

    # ---------- security ----------

    def security(self, collected: str) -> dict[str, Any]:
        hosts, flows, auth, dns = [], [], [], []
        for site in BRANCHES:
            for lease in self.leases(site):
                hosts.append({"ip": str(lease.ip_address), "hostname": lease.hostname or f"{site.lower()}-host", "site_id": site, "role": "workstation",
                              "mac": lease.mac_address})
            hosts.append({"ip": f"10.{SITE_CODE[site]}.10.20", "hostname": f"{site.lower()}-prn-01", "site_id": site, "role": "printer", "mac": mac("printer", site)})
        for server in (d for d in self.topology.devices if d.device_type == DeviceType.SERVER):
            hosts.append({"ip": str(server.management_ip), "hostname": server.device_id.lower(), "site_id": "DC1", "role": "server"})
        hosts += [{"ip": SCANNER_IP, "hostname": "dc1-vscan-01", "site_id": "DC1", "role": "scanner"},
                  {"ip": BACKUP_IP, "hostname": "dc1-bkp-01", "site_id": "DC1", "role": "backup"},
                  {"ip": JUMP_HOST_IP, "hostname": "noc-jump-01", "site_id": "CORE", "role": "jump_host"}]
        n = 0

        def flow(start: str, src: str, dst: str, port: int | None, proto: str, out: int, inn: int, state: str, sensor: str, duration: float = 4.0) -> None:
            nonlocal n
            n += 1
            flows.append({"flow_id": f"FL-{n:05d}", "start": start, "duration_seconds": duration, "src_ip": src, "dst_ip": dst, "dst_port": port,
                          "protocol": proto, "bytes_out": out, "bytes_in": inn, "packets": max(2, (out + inn) // 900), "state": state, "sensor_device_id": sensor})

        for site in BRANCHES:
            for index, lease in enumerate(self.leases(site)[:6]):
                ip = str(lease.ip_address)
                for minute in (-14, -4, 6, 16):
                    flow(self.at(minute + index * 0.3), ip, APP_SERVER_IP, 443, "tcp", whole(20_000, 80_000, ip, minute), whole(200_000, 2_000_000, ip, minute, 1),
                         "established", "DC1-FW-01", between(2, 40, ip, minute))
                    flow(self.at(minute + index * 0.3 + 0.1), ip, "10.100.100.10", 53, "udp", 80, 140, "established", "DC1-FW-01", 0.05)
                flow(self.at(-8 + index), ip, INTERNET_HOST, 443, "tcp", whole(10_000, 60_000, "web", ip), whole(100_000, 900_000, "web", ip), "established", "CORE-FW-01")
                for minute in (-17, -2, 13):  # software update checks every 15 minutes: periodic, but allowlisted
                    flow(self.at(minute + index * 0.2), ip, UPDATE_HOST, 443, "tcp", 2400, 5100, "established", "CORE-FW-01", 1.2)
                auth.append({"auth_id": f"AU-{site}-{index}", "timestamp": self.at(-16 + index), "src_ip": ip, "dst_host": "dc1-srv-auth-01",
                             "account": f"user.{site.lower()}{index:02d}", "protocol": "kerberos", "result": "success"})
                dns.append({"log_id": f"DNS-{site}-{index}", "timestamp": self.at(-14 + index), "client_ip": ip, "qname": "erp.corp.example.com",
                            "qtype": "A", "response_bytes": 92})
            first = str(self.leases(site)[0].ip_address)
            auth.append({"auth_id": f"AU-{site}-typo", "timestamp": self.at(-11), "src_ip": first, "dst_host": "dc1-srv-auth-01",
                         "account": f"user.{site.lower()}00", "protocol": "kerberos", "result": "failure"})
        for device in ("CORE-RTR-01", "CORE-RTR-02", "NYC-RTR-01"):
            target = str(self.devices[device].management_ip)
            flow(self.at(-19), JUMP_HOST_IP, target, 22, "tcp", 9_000, 40_000, "established", "CORE-FW-01", 60)
            auth.append({"auth_id": f"AU-JUMP-{device}", "timestamp": self.at(-19), "src_ip": JUMP_HOST_IP, "dst_host": device.lower(),
                         "account": "netops", "protocol": "ssh", "result": "success"})
        collected_from = ["BLR-SW-01", "CORE-FW-01", "DC1-FW-01", "NYC-SW-01", "SIN-SW-01"]
        return {"collected_from": collected_from, "collected_at": collected, "hosts": hosts, "flows": flows, "auth": auth, "dns_logs": dns, "alerts": [],
                "intel": [{"indicator": "192.0.2.66", "kind": "ip", "label": "Synthetic test indicator (command-and-control test address)", "synthetic": True},
                          {"indicator": "203.0.113.250", "kind": "ip", "label": "Synthetic test indicator (exfiltration test address)", "synthetic": True},
                          {"indicator": "exfil-relay.test", "kind": "domain", "label": "Synthetic test indicator (tunnelling test domain)", "synthetic": True}],
                "allowlist": {"scanners": [SCANNER_IP], "jump_hosts": [JUMP_HOST_IP], "backup_servers": [BACKUP_IP],
                              "periodic_destinations": [UPDATE_HOST, "updates.example.com"], "maintenance": []}}


def network_of(prefix: str) -> IPv4Network:
    return IPv4Network(prefix)


def address(value: str) -> IPv4Address:
    return IPv4Address(value)
