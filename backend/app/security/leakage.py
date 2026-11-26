import re
from collections.abc import Iterable

from app.engine.instructions import SYSTEM_INSTRUCTIONS
from app.security.secrets import contains_secret

SHINGLE_SIZE = 6
WORD = re.compile(r"[a-z0-9]+")
ENVIRONMENT_ASSIGNMENT = re.compile(
    r"\b(OPENAI_API_KEY|FOUNDRY_API_KEY|AI_ENDPOINT|AI_MODEL|AI_PROVIDER|INCIDENT_STORE_DIR)\s*[:=]\s*\S+", re.IGNORECASE)
INTERNAL_MARKERS = ("untrusted_incident", "triage_hints", "untrusted_reference_documents", "output_schema", "evidence_rule",
                    "untrusted_data_notice")


def shingles(text: str) -> set[tuple[str, ...]]:
    words = WORD.findall(text.lower())
    return {tuple(words[index:index + SHINGLE_SIZE]) for index in range(len(words) - SHINGLE_SIZE + 1)}


INSTRUCTION_SHINGLES = shingles(SYSTEM_INSTRUCTIONS)


def leakage_categories(texts: Iterable[str], known_secrets: Iterable[str] = ()) -> list[str]:
    combined = "\n".join(text for text in texts if text)
    lowered = combined.lower()
    categories = []
    if shingles(combined) & INSTRUCTION_SHINGLES:
        categories.append("system_instructions")
    if contains_secret(combined) or any(secret and len(secret) >= 8 and secret in combined for secret in known_secrets):
        categories.append("secret")
    if ENVIRONMENT_ASSIGNMENT.search(combined):
        categories.append("configuration")
    if any(marker in lowered for marker in INTERNAL_MARKERS):
        categories.append("internal_prompt")
    return categories
