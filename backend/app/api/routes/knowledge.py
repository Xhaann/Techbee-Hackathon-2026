from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query
from pydantic import ValidationError

from app.api.dependencies import PageDependency, ServicesDependency, invalid, not_found, require
from app.api.schemas import Page
from app.engine.schema import FaultDomain
from app.knowledge import DiagnosticProcedure, KnowledgeNotFoundError, KnowledgeQuery, Playbook, RecordType, RetrievalResult, Runbook
from app.knowledge.models import KnowledgeCategory
from app.network.models import Identifier
from app.security.permissions import Permission

router = APIRouter(prefix="/knowledge", tags=["knowledge"], dependencies=[Depends(require(Permission.VIEW_DIAGNOSTICS))])


@router.get("/playbooks", response_model=Page[Playbook])
def playbooks(registry: ServicesDependency, page: PageDependency, fault_domain: FaultDomain | None = None,
              category: KnowledgeCategory | None = None) -> dict:
    return page.slice(registry.knowledge.repository.list(record_type=RecordType.PLAYBOOK, fault_domain=fault_domain,
                                                         category=category))


@router.get("/playbooks/{playbook_id}", response_model=Playbook)
def playbook(registry: ServicesDependency, playbook_id: Annotated[str, Path(pattern=r"^PB-[A-Z0-9-]+$", max_length=64)]) -> Playbook:
    try:
        record = registry.knowledge.repository.get(playbook_id)
    except KnowledgeNotFoundError:
        raise not_found(f"Unknown playbook '{playbook_id}'") from None
    if not record.active:
        raise not_found(f"Unknown playbook '{playbook_id}'")
    return record


@router.get("/runbooks", response_model=Page[Runbook])
def runbooks(registry: ServicesDependency, page: PageDependency, site_id: Identifier | None = None) -> dict:
    return page.slice(registry.knowledge.repository.list(record_type=RecordType.RUNBOOK, site_id=site_id))


@router.get("/procedures", response_model=Page[DiagnosticProcedure])
def procedures(registry: ServicesDependency, page: PageDependency, fault_domain: FaultDomain | None = None) -> dict:
    return page.slice(registry.knowledge.repository.list(record_type=RecordType.PROCEDURE, fault_domain=fault_domain))


@router.get("/search", response_model=RetrievalResult)
def search(registry: ServicesDependency, q: Annotated[str, Query(max_length=500)] = "",
           fault_domain: FaultDomain | None = None, site_id: Identifier | None = None,
           limit: Annotated[int, Query(ge=1, le=10)] = 5) -> RetrievalResult:
    try:
        query = KnowledgeQuery(text=q, fault_domain=fault_domain, site_id=site_id, limit=limit)
    except ValidationError:
        raise invalid("A search requires query text, a fault domain or a site") from None
    return registry.knowledge.search(query)
