from collections import deque
from typing import NamedTuple

from app.network.models import Link


class Hop(NamedTuple):
    parent: str | None
    link: Link | None
    depth: int


Adjacency = dict[str, list[tuple[str, Link]]]


def build_adjacency(links: list[Link]) -> Adjacency:
    adjacency: Adjacency = {}
    for link in links:
        adjacency.setdefault(link.a_device_id, []).append((link.b_device_id, link))
        adjacency.setdefault(link.b_device_id, []).append((link.a_device_id, link))
    for neighbors in adjacency.values():
        neighbors.sort(key=lambda item: (item[0], item[1].link_id))
    return adjacency


def breadth_first(adjacency: Adjacency, source: str) -> dict[str, Hop]:
    tree = {source: Hop(None, None, 0)}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        for neighbor, link in adjacency.get(node, []):
            if neighbor not in tree:
                tree[neighbor] = Hop(node, link, tree[node].depth + 1)
                queue.append(neighbor)
    return tree


def shortest_path(adjacency: Adjacency, source: str, target: str) -> tuple[list[str], list[str]] | None:
    tree = breadth_first(adjacency, target)
    if source not in tree:
        return None
    devices, links = [source], []
    while devices[-1] != target:
        hop = tree[devices[-1]]
        devices.append(hop.parent)
        links.append(hop.link.link_id)
    return devices, links


def orient(link: Link, device_id: str) -> tuple[str, str]:
    if link.a_device_id == device_id:
        return link.a_interface_id, link.b_interface_id
    return link.b_interface_id, link.a_interface_id
