"""Reads pasted output of the Phase 3 verification commands and says what it shows.

Each reader recognises one command's output by a signature that only that output has, then compares it with what
healthy output looks like. Pasted text is data: nothing in it is executed or obeyed. Returns None when the text is not
one of these outputs, so the Phase 2 readers keep handling everything else.
"""
import re
from typing import Any

SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("show spanning-tree detail", re.compile(r"Number of topology changes \d+|VLAN\d{4} is executing the", re.I)),
    ("show mac address-table notification mac-move", re.compile(r"Mac Move Notification|MAC address\s+Vlan\s+From Mod/Port", re.I)),
    ("show ip arp", re.compile(r"Protocol\s+Address\s+Age \(min\)\s+Hardware Addr", re.I)),
    ("show interfaces trunk", re.compile(r"Port\s+Mode\s+Encapsulation\s+Status\s+Native vlan|Vlans allowed on trunk", re.I)),
    ("show ip ospf database", re.compile(r"OSPF Router with ID .*Process ID|Router Link States \(Area|LS age:\s+\d+", re.I)),
    ("show ip bgp prefix", re.compile(r"BGP routing table entry for", re.I)),
    ("show running ippool", re.compile(r"NAT pool|ippool|Translations\s*:\s*\d+|allocation fail", re.I)),
    ("show crypto ikev2 sa", re.compile(r"Tunnel-id\s+Local\s+Remote\s+fvrf/ivrf\s+Status|IKEv2 SAs:", re.I)),
    ("show vpn ike-sa", re.compile(r"IKEv2 SAs|Gateway ID\s+Peer-Address", re.I)),
    ("ping df-bit", re.compile(r"Packet sent with the DF bit set", re.I)),
    ("show policy-map interface", re.compile(r"Service-policy output:|Class-map: \S+ \(match-", re.I)),
    ("show ipv6 ospf neighbor", re.compile(r"OSPFv3 Router with ID|Neighbor ID\s+Pri\s+State\s+Dead Time\s+Interface ID", re.I)),
    ("show ipv6 route", re.compile(r"IPv6 Routing Table - default", re.I)),
    ("show ap auto-rf", re.compile(r"Noise Profile|Interference Profile|Channel Utilization\s*:", re.I)),
    ("show ip pim rp mapping", re.compile(r"PIM Group-to-RP Mappings", re.I)),
    ("show ip mroute", re.compile(r"IP Multicast Routing Table|Incoming interface: .*RPF nbr", re.I)),
    ("openssl s_client", re.compile(r"CONNECTION ESTABLISHED|Verify return code:|Verification error:|verify error:num=", re.I)),
    ("show log threat", re.compile(r"threat\s*/\s*content|spyware|vulnerability.*severity", re.I)),
]


def recognises(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in SIGNATURES)


def lines_with(text: str, pattern: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if re.search(pattern, line, re.I)][:3]


def read(text: str) -> dict[str, Any] | None:
    command = next((name for name, pattern in SIGNATURES if pattern.search(text)), None)
    if command is None:
        return None
    verdict, summary, key = "unclear", "I recognise the output but can't tell from this part whether it is healthy; paste the whole output.", []
    if command == "show spanning-tree detail":
        changes = [int(x) for x in re.findall(r"Number of topology changes (\d+)", text, re.I)]
        recent = re.search(r"last change occurred (\d+):(\d+):(\d+) ago", text, re.I)
        seconds = int(recent.group(1)) * 3600 + int(recent.group(2)) * 60 + int(recent.group(3)) if recent else None
        source = re.search(r"from (\S+)", text.split("last change occurred", 1)[1]) if "last change occurred" in text else None
        if changes and max(changes) > 50 and seconds is not None and seconds < 600:
            verdict = "fault"
            summary = (f"{max(changes)} topology changes, the last {seconds} s ago" + (f" from {source.group(1)}" if source else "")
                       + ": the topology keeps changing, which is what a loop or a flapping port looks like.")
        elif changes:
            verdict, summary = "healthy", f"{max(changes)} topology changes in total and nothing recent: spanning tree is stable."
        key = lines_with(text, r"topology changes|last change occurred")
    elif command == "show mac address-table notification mac-move":
        moves = lines_with(text, r"\d{4}\.\w{4}\.\w{4}|\w\w:\w\w:\w\w")
        verdict, summary = ("fault", "MACs are moving between ports: frames are looping or a host is attached twice.") if moves else \
            ("healthy", "No MAC moves recorded.")
        key = moves
    elif command == "show ip arp":
        rows = re.findall(r"Internet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+([0-9a-f.:]+)", text, re.I)
        by_ip: dict[str, set[str]] = {}
        for ip, mac in rows:
            by_ip.setdefault(ip, set()).add(mac.lower())
        doubled = [ip for ip, macs in by_ip.items() if len(macs) > 1]
        by_mac: dict[str, set[str]] = {}
        for ip, mac in rows:
            by_mac.setdefault(mac.lower(), set()).add(ip)
        greedy = [mac for mac, ips in by_mac.items() if len(ips) >= 5]
        if doubled:
            verdict, summary = "fault", f"{doubled[0]} resolves to more than one MAC: an address conflict or someone answering for it."
        elif greedy:
            verdict, summary = "fault", f"{greedy[0]} answers for {len(by_mac[greedy[0]])} addresses: unless it is a router, that is a spoofing pattern."
        elif rows:
            verdict, summary = "healthy", f"{len(rows)} entries, one MAC per address. Compare the gateway's MAC with the one you expect."
        key = lines_with(text, "|".join(re.escape(ip) for ip in doubled) or r"Internet")
    elif command == "show interfaces trunk":
        natives = re.findall(r"^\s*(\S+)\s+(?:on|desirable|auto|nonegotiate)\s+802\.1q\s+\S+\s+(\d+)", text, re.I | re.M)
        allowed = re.findall(r"^\s*(\S+)\s+([\d,\-]+)\s*$", text.split("Vlans allowed on trunk", 1)[1], re.M) if "Vlans allowed on trunk" in text else []
        if natives:
            ports = ", ".join(f"{p} native {n}" for p, n in natives)
            listed = "; ".join(f"{p} allows {v}" for p, v in allowed[:2])
            verdict = "healthy" if all(n == "1" for _, n in natives) else "fault"
            summary = (f"{ports}" + (f"; {listed}" if listed else "") + (". Compare with the far end: both sides must list the same VLANs and native VLAN."
                       if verdict == "healthy" else ". A native VLAN other than the far end's puts untagged frames in the wrong VLAN."))
        key = lines_with(text, r"802\.1q|Vlans allowed")
    elif command == "show ip ospf database":
        ages = [int(x) for x in re.findall(r"LS age:\s+(\d+)", text)]
        maxage = [a for a in ages if a >= 3600]
        if maxage:
            verdict, summary = "fault", f"{len(maxage)} LSA(s) at MaxAge (3600 s): the router that owns them has stopped refreshing them."
        elif ages:
            verdict, summary = "healthy", "All LSAs are younger than MaxAge. Compare sequence numbers with another router's copy to confirm they match."
        else:
            verdict, summary = "unclear", "Database summary only. Run it with 'router <id>' on two routers and compare sequence numbers."
        key = lines_with(text, r"LS age|Sequence Number|Advertising Router")
    elif command == "show ip bgp prefix":
        paths = re.findall(r"^\s*((?:\d+ )*\d+)\s*$", text, re.M)
        origin = paths[0].split()[-1] if paths else None
        verdict = "unclear"
        summary = (f"The best path ends in AS{origin}: compare it with the AS registered for this prefix." if origin
                   else "The prefix is in the table; check which AS originates it.")
        key = lines_with(text, r"BGP routing table entry|^\s*\d+(?: \d+)*\s*$|Local")
    elif command == "show running ippool":
        used = re.search(r"(\d+)\s*%", text)
        failures = re.search(r"allocation fail\w*\D+(\d+)", text, re.I)
        if (used and int(used.group(1)) >= 95) or (failures and int(failures.group(1)) > 0):
            verdict, summary = "fault", "The NAT pool is full and refusing new translations: new outbound sessions fail."
        elif used:
            verdict, summary = "healthy", f"The pool is {used.group(1)}% used with no allocation failures."
        key = lines_with(text, r"%|fail")
    elif command in ("show crypto ikev2 sa", "show vpn ike-sa"):
        if re.search(r"\bREADY\b|\bEstablished\b|\bmature\b", text, re.I):
            verdict, summary = "healthy", "The IKE SA is up."
        else:
            verdict, summary = "fault", "No established IKE SA: the tunnel is not negotiating (check the proposals and reachability of the peer)."
        key = lines_with(text, r"READY|Established|DELETE|IN-NEG|\d{1,3}(?:\.\d{1,3}){3}/\d+")
    elif command == "ping df-bit":
        rate = re.search(r"Success rate is (\d+) percent", text)
        size = re.search(r"(\d+)-byte", text)
        frag = "M" in "".join(lines_with(text, r"^[.!M]+$"))
        if rate and int(rate.group(1)) == 0 and not frag:
            verdict, summary = "fault", (f"{size.group(1) if size else 'These'}-byte packets with DF set vanish and no 'fragmentation needed' reply comes "
                                         "back: a path-MTU black hole. Try a smaller size to find the limit.")
        elif rate and int(rate.group(1)) == 0 and frag:
            verdict, summary = "fault", "The path MTU is smaller than this size, and the network says so (M replies): lower the size or clamp the MSS."
        elif rate:
            verdict, summary = "healthy", f"{size.group(1) if size else 'This'}-byte packets get through without fragmentation."
        key = lines_with(text, r"Success rate|DF bit|^[.!M]+$")
    elif command == "show policy-map interface":
        drops = re.findall(r"Class-map: (\S+).*?(?:drops|total drops)\s*(\d+)", text, re.I | re.S)
        voice = re.search(r"Class-map: VOICE.*?(\d+) packets", text, re.I | re.S)
        if voice and voice.group(1) == "0":
            verdict, summary = "fault", "The VOICE class matched 0 packets: voice is not being classified into the priority queue."
        elif any(name.upper().startswith("VOICE") and int(n) > 0 for name, n in drops):
            verdict, summary = "fault", "The priority class is dropping: voice exceeds its allocation."
        elif drops:
            verdict, summary = "healthy", "Voice is classified and not dropped. Drops in scavenger or class-default under load are expected."
        key = lines_with(text, r"Class-map|drops")
    elif command == "show ipv6 ospf neighbor":
        rows = lines_with(text, r"\bFULL\b|\bINIT\b|\bDOWN\b|\bEXSTART\b|\b2WAY\b")
        verdict, summary = ("healthy", "The OSPFv3 neighbour is FULL.") if rows and all("FULL" in r for r in rows) else \
            ("fault", "No FULL OSPFv3 neighbour: IPv6 routes will not be learned (check the area and interface settings on both ends).")
        key = rows
    elif command == "show ipv6 route":
        default = re.search(r"^\s*\w+\s+::/0", text, re.M)
        verdict, summary = ("healthy", "An IPv6 default route is present.") if default else \
            ("fault", "No IPv6 default route (::/0): IPv6 traffic cannot leave the site.")
        key = lines_with(text, r"::/0|IPv6 Routing Table")
    elif command == "show ap auto-rf":
        noise = [int(x) for x in re.findall(r"(-\d{2,3})\s*dBm", text)]
        interference = [int(x) for x in re.findall(r"Interference\s*:?\s*(\d+)\s*%", text, re.I)]
        if (noise and max(noise) > -85) or (interference and max(interference) >= 25):
            verdict, summary = "fault", "Noise or non-Wi-Fi interference is high on this radio: find the source near the AP or move the channel."
        elif noise or interference:
            verdict, summary = "healthy", "Noise and interference are at normal levels."
        key = lines_with(text, r"Noise|Interference|Utilization")
    elif command == "show ip pim rp mapping":
        rps = sorted(set(re.findall(r"RP (\d{1,3}(?:\.\d{1,3}){3})", text)))
        verdict = "healthy" if rps == ["10.255.0.1"] else "fault" if rps else "unclear"
        summary = (f"The group maps to RP {', '.join(rps)}" + ("." if verdict == "healthy" else "; every router should use 10.255.0.1.")) if rps \
            else "No RP mapping shown."
        key = lines_with(text, r"RP \d")
    elif command == "show ip mroute":
        zero = re.search(r"Incoming interface: Null|RPF nbr 0\.0\.0\.0|Registering", text)
        verdict, summary = ("fault", "The multicast route has no valid incoming interface: the RPF check towards the source or RP fails.") if zero else \
            ("healthy", "The multicast route has an incoming interface and outgoing interfaces.")
        key = lines_with(text, r"Incoming interface|Outgoing interface")
    elif command == "openssl s_client":
        if re.search(r"certificate has expired", text, re.I):
            verdict, summary = "fault", "The server's certificate has expired: renew it on the server. The network is not involved."
        elif re.search(r"self[- ]signed|unable to get local issuer|unknown ca", text, re.I):
            verdict, summary = "fault", ("The certificate is not from a trusted CA. If this is an internal service that normally verifies, something "
                                         "may be presenting its own certificate: compare the fingerprint with the server's.")
        elif re.search(r"hostname mismatch|does not match", text, re.I):
            verdict, summary = "fault", "The certificate doesn't cover the name you connected to."
        elif re.search(r"Verify return code: 0|Verification: OK", text, re.I):
            verdict, summary = "healthy", "The certificate verifies."
        key = lines_with(text, r"Verif|notAfter|issuer|subject")
    elif command == "show log threat":
        rows = lines_with(text, r"critical|high|medium")
        verdict, summary = ("fault", "Threat log entries are present: review them with the security team before drawing conclusions.") if rows else \
            ("healthy", "No threat log entries.")
        key = rows
    return {"command": command, "verdict": verdict, "summary": summary, "evidence_lines": key[:3]}


ALTERNATIVES = {"show spanning-tree detail": "show spanning-tree summary", "show ip arp": "show arp", "show interfaces trunk": "show interfaces switchport",
                "show ip ospf database": "show ospf database", "show crypto ikev2 sa": "show crypto session", "show running ippool": "show session info",
                "show policy-map interface": "show class-map", "show ipv6 ospf neighbor": "show ospfv3 neighbor", "show ap auto-rf": "show ap summary",
                "show ip pim rp mapping": "show ip pim rp", "show ip mroute": "show ip mroute summary"}
