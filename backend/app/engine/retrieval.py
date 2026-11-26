from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.network.models import Identifier


class RetrievedDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: Identifier
    title: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=4000)


class Retriever(Protocol):
    def search(self, query: str, limit: int) -> list[RetrievedDocument]: ...


class NoRetrieval:
    def search(self, query: str, limit: int) -> list[RetrievedDocument]:
        return []
