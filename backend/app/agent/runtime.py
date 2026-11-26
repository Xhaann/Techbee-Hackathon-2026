from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx2
import openai
from agent_framework import Agent
from agent_framework.openai import OpenAIChatCompletionClient

from app.agent.tools import KNOWLEDGE_TOOL, ToolBudget, build_tools
from app.core.config import Settings
from app.engine.engine import MAX_MODEL_TURNS
from app.engine.instructions import SYSTEM_INSTRUCTIONS
from app.engine.providers import ProviderConfig, ProviderError, ProviderErrorKind, build_provider_config

AGENT_NAME = "network-incident-diagnosis-agent"
MAX_RUN_SECONDS = 300.0
AGENT_WORKFLOW = f"""

Agent workflow
- Start from the incident_understanding supplied in the first user message. Its entities were validated against the topology; values listed as unknown must stay unknown.
- Plan which checks are needed before calling tools, then call one tool at a time and adapt to each result.
- You may call {KNOWLEDGE_TOOL} for playbook or runbook guidance. It returns unverified guidance, never evidence, and it uses the same tool budget.
- If the incident report and the collected evidence disagree, say so, keep confidence low and recommend read-only checks to resolve the conflict.
- You cannot modify incidents, devices or configuration. A human must review every conclusion."""
AGENT_INSTRUCTIONS = SYSTEM_INSTRUCTIONS + AGENT_WORKFLOW


@dataclass(frozen=True)
class AgentModel:
    name: str
    model: str
    config: ProviderConfig

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> Any:
        raise ProviderError(ProviderErrorKind.CONFIGURATION, "The agent drives the model through Microsoft Agent Framework")


def agent_model(settings: Settings) -> AgentModel:
    config = build_provider_config(settings)
    if config.name != "openai":
        raise ProviderError(ProviderErrorKind.CONFIGURATION, "The local agent supports AI_PROVIDER=openai only")
    return AgentModel(name=config.name, model=config.model, config=config)


class AgentResources:
    def __init__(self, settings: Settings, transport: Any = None) -> None:
        self.transport = transport
        self.client: httpx2.AsyncClient | None = None
        self.model: AgentModel | None = None
        self.error: str | None = None
        if settings.ai_provider != "disabled":
            try:
                self.model = agent_model(settings)
            except ProviderError as exc:
                self.error = exc.message

    async def start(self) -> None:
        if self.model is not None and self.client is None:
            self.client = httpx2.AsyncClient(transport=self.transport)

    async def close(self) -> None:
        if self.client is not None:
            await self.client.aclose()
            self.client = None

    @asynccontextmanager
    async def http_client(self) -> AsyncIterator[httpx2.AsyncClient]:
        if self.client is not None:
            yield self.client
            return
        async with httpx2.AsyncClient(transport=self.transport) as client:
            yield client


def run_deadline(config: ProviderConfig) -> float:
    return min(MAX_RUN_SECONDS, config.timeout_seconds * (MAX_MODEL_TURNS + 1))


def build_agent(model: AgentModel, budget: ToolBudget, http_client: Any = None) -> Agent:
    config = model.config
    async_client = openai.AsyncOpenAI(api_key=config.api_key.get_secret_value(), base_url=config.endpoint,
                                      timeout=config.timeout_seconds, max_retries=0, http_client=http_client)
    client = OpenAIChatCompletionClient(model=config.model, async_client=async_client)
    client.function_invocation_configuration.update({
        "max_function_calls": budget.limit, "max_iterations": MAX_MODEL_TURNS, "max_duration_seconds": run_deadline(config),
        "allow_concurrent_invocation": False, "terminate_on_unknown_calls": False, "include_detailed_errors": False,
    })
    options: dict[str, Any] = {"max_tokens": config.max_output_tokens, "allow_multiple_tool_calls": False}
    if config.temperature is not None:
        options["temperature"] = config.temperature
    return Agent(client=client, instructions=AGENT_INSTRUCTIONS, name=AGENT_NAME, tools=build_tools(budget),
                 default_options=options)


COMPOSER_NAME = "network-ops-conversation"
MAX_COMPOSER_TOKENS = 900


def build_composer(model: AgentModel, instructions: str, http_client: Any = None) -> Agent:
    """A tool-less agent that only writes conversational replies; it cannot call diagnostic tools."""
    config = model.config
    async_client = openai.AsyncOpenAI(api_key=config.api_key.get_secret_value(), base_url=config.endpoint,
                                      timeout=config.timeout_seconds, max_retries=0, http_client=http_client)
    client = OpenAIChatCompletionClient(model=config.model, async_client=async_client)
    options: dict[str, Any] = {"max_tokens": min(MAX_COMPOSER_TOKENS, config.max_output_tokens)}
    if config.temperature is not None:
        options["temperature"] = config.temperature
    return Agent(client=client, instructions=instructions, name=COMPOSER_NAME, default_options=options)
