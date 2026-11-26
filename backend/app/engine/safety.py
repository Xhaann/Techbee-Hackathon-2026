import ipaddress
import re

READ_ONLY_PREFIXES = (
    "show ", "display ", "ping ", "traceroute ", "dig ", "nslookup ", "journalctl ",
    "rndc status", "rndc zonestatus ", "keactrl status",
)
FORBIDDEN_TOKENS = re.compile(
    r"(;|&&|\|\||`|\$\(|>|<|\bconf(igure)?\b|\bwrite\b|\berase\b|\bdelete\b|\breload\b|\bshutdown\b|\bno\s|\bclear\b"
    r"|\bcopy\b|\bset\b|\bcommit\b|\brm\b|\brestart\b|\bstop\b|\bkill\b|\breboot\b|\bdebug\b|\bformat\b|\brequest\b"
    r"|\bsudo\b|\btee\b|\bcurl\b|\bwget\b|\bssh\b|\btelnet\b|\bsnmp\w*\b)",
    re.IGNORECASE,
)
REMEDIATION_PHRASES = re.compile(
    r"\b(configure terminal|conf t|no shutdown|shutdown the|reload the|clear ip|write memory|commit the|"
    r"apply the fix|change the configuration|delete the rule|restart the service)\b",
    re.IGNORECASE,
)
INJECTION_PATTERNS = (
    re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules|prompt|guidelines)\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"</?\s*(system|assistant|developer)\s*>", re.IGNORECASE),
    re.compile(r"\b(run|execute)\b.{0,30}\b(command|shell|script|code)\b", re.IGNORECASE),
    re.compile(r"\b(reveal|print|show)\b.{0,30}\b(api[\s_-]?key|secret|password|credential)s?\b", re.IGNORECASE),
    re.compile(r"\bcall\b.{0,20}\btool\b", re.IGNORECASE),
)


ALLOWED_CHARACTERS = re.compile(r'^[A-Za-z0-9 ./:_@{}"=,|-]+$')
SENSITIVE_TOKENS = re.compile(
    r"(running-config|startup-config|tech-support|\bcrypto\b|\bkeys?\b|\bpasswords?\b|\bsecrets?\b|\bcredentials?\b"
    r"|\bcertificates?\b|\bprivate\b|\bredirect\b|\bappend\b|\b(?:tftp|ftp|scp|sftp|https?|file|flash|bootflash|disk0|nvram):)",
    re.IGNORECASE,
)
OUTPUT_FILTER = re.compile(r"\|\s*(include|exclude|begin|section|count)\b", re.IGNORECASE)
PLACEHOLDER = re.compile(r"^\{[a-z_]+\}$")
SAFE_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
SAFE_HOSTNAME = re.compile(r"^(?:[a-z0-9-]+\.)*example\.(?:com|org|net)$", re.IGNORECASE)


def allowed_target(token: str) -> bool:
    if PLACEHOLDER.match(token) or SAFE_HOSTNAME.match(token):
        return True
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return False
    return any(address in network for network in SAFE_NETWORKS)


def targets_are_safe(words: list[str]) -> bool:
    verb = words[0].lower()
    if verb in ("ping", "traceroute"):
        return len(words) > 1 and allowed_target(words[1])
    if verb == "dig":
        servers = [word[1:] for word in words[1:] if word.startswith("@")]
        names = [word for word in words[1:] if not word.startswith(("@", "-")) and word.upper() not in ("A", "AAAA", "MX", "PTR")]
        return all(allowed_target(item) for item in servers + names) and bool(names)
    return True


def is_read_only_command(command: str) -> bool:
    if not isinstance(command, str):
        return False
    normalized = " ".join(command.strip().split())
    if not normalized or len(normalized) > 200 or not ALLOWED_CHARACTERS.match(normalized):
        return False
    if not any(normalized.lower().startswith(prefix) or normalized.lower() == prefix.strip()
               for prefix in READ_ONLY_PREFIXES):
        return False
    if FORBIDDEN_TOKENS.search(normalized) or SENSITIVE_TOKENS.search(normalized):
        return False
    if normalized.count("|") != len(OUTPUT_FILTER.findall(normalized)):
        return False
    return targets_are_safe(normalized.split(" "))


def mentions_remediation(text: str) -> bool:
    return REMEDIATION_PHRASES.search(text) is not None


def injection_flags(source: str, text: str) -> list[str]:
    if any(pattern.search(text) for pattern in INJECTION_PATTERNS):
        return [f"Possible prompt injection detected in {source}; treated as untrusted data"]
    return []
