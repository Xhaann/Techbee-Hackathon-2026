from typing import Annotated

from fastapi import APIRouter, Depends, Path

from app.api.dependencies import PageDependency, not_found, require, tool_data
from app.api.schemas import Page
from app.diagnostics import ToolResult, get_topology
from app.network.models import (
    Device,
    DeviceType,
    Identifier,
    Interface,
    Link,
    LinkType,
    NetworkPath,
    NetworkTopology,
    PathService,
    Site,
)
from app.network.repository import load_topology
from app.security.permissions import Permission

router = APIRouter(prefix="/topology", tags=["topology"], dependencies=[Depends(require(Permission.VIEW_DIAGNOSTICS))])
DevicePath = Annotated[str, Path(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$", max_length=64)]
SitePath = Annotated[str, Path(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$", max_length=32)]


def find_device(device_id: str) -> Device:
    device = next((d for d in load_topology().devices if d.device_id == device_id), None)
    if device is None:
        raise not_found(f"Unknown device '{device_id}'")
    return device


@router.get("", response_model=NetworkTopology)
def topology() -> NetworkTopology:
    return load_topology()


@router.get("/sites", response_model=Page[Site])
def sites(page: PageDependency) -> dict:
    return page.slice(load_topology().sites)


@router.get("/sites/{site_id}", response_model=ToolResult)
def site(site_id: SitePath) -> ToolResult:
    return tool_data(get_topology(site_id))


@router.get("/devices", response_model=Page[Device])
def devices(page: PageDependency, site_id: Identifier | None = None, device_type: DeviceType | None = None) -> dict:
    selected = [d for d in load_topology().devices
                if (site_id is None or d.site_id == site_id) and (device_type is None or d.device_type == device_type)]
    return page.slice(selected)


@router.get("/devices/{device_id}", response_model=Device)
def device(device_id: DevicePath) -> Device:
    return find_device(device_id)


@router.get("/devices/{device_id}/interfaces", response_model=Page[Interface])
def interfaces(device_id: DevicePath, page: PageDependency) -> dict:
    find_device(device_id)
    return page.slice([i for i in load_topology().interfaces if i.device_id == device_id])


@router.get("/links", response_model=Page[Link])
def links(page: PageDependency, link_type: LinkType | None = None) -> dict:
    return page.slice([link for link in load_topology().links if link_type is None or link.link_type == link_type])


@router.get("/services", response_model=Page[NetworkPath])
def services(page: PageDependency, site_id: Identifier | None = None, service: PathService | None = None) -> dict:
    selected = [p for p in load_topology().paths
                if (site_id is None or p.source_site_id == site_id) and (service is None or p.service == service)]
    return page.slice(selected)
