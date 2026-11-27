"""Common names people use for the synthetic sites, shared by every entry point that reads free text."""

SITE_ALIASES: dict[str, str] = {
    "bangalore": "BLR", "bengaluru": "BLR", "new york": "NYC", "nyc": "NYC", "singapore": "SIN", "london": "CORE",
    "slough": "DC1", "data centre": "DC1", "data center": "DC1", "datacenter": "DC1", "datacentre": "DC1",
}
# "NY" counts only when written in capitals, so "ny" inside ordinary words or chat shorthand never matches.
UPPERCASE_ONLY_ALIASES: dict[str, str] = {"NY": "NYC"}


def aliases_for(site_id: str) -> tuple[str, ...]:
    return tuple(alias for alias, target in SITE_ALIASES.items() if target == site_id)
