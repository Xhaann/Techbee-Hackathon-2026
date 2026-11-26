from app.core.config import Settings
from app.diagnostics.common import MAX_EVIDENCE, MAX_RECORDS, MAX_TIME_RANGE
from app.engine.engine import MAX_DOCUMENTS, MAX_MODEL_TURNS
from app.engine.executor import MAX_ARGUMENT_CHARS, MAX_RESULT_CHARS, MAX_TOOL_CALLS, MAX_TOOL_REQUESTS
from app.engine.providers import MAX_CONTENT_CHARS, MAX_RESPONSE_BYTES
from app.incidents.models import IncidentFilter
from app.incidents.repository import MAX_RECORD_BYTES
from app.knowledge.repository import MAX_FILE_BYTES
from app.knowledge.retrieval import KnowledgeQuery
from app.network.repository import MAX_DATASET_BYTES


def field_maximum(model: type, field: str) -> int:
    return next(item.le for item in model.model_fields[field].metadata if getattr(item, "le", None) is not None)


def resource_limits(settings: Settings) -> dict[str, int | float]:
    return {
        "request_body_bytes": settings.max_request_bytes,
        "rate_limit_requests": settings.rate_limit_requests,
        "rate_limit_window_seconds": settings.rate_limit_window_seconds,
        "concurrent_requests": settings.max_concurrent_requests,
        "network_dataset_bytes": MAX_DATASET_BYTES,
        "incident_file_bytes": MAX_RECORD_BYTES,
        "knowledge_dataset_bytes": MAX_FILE_BYTES,
        "ai_timeout_seconds": settings.ai_timeout_seconds,
        "ai_max_output_tokens": settings.ai_max_output_tokens,
        "ai_response_bytes": MAX_RESPONSE_BYTES,
        "ai_content_chars": MAX_CONTENT_CHARS,
        "ai_model_turns": MAX_MODEL_TURNS,
        "ai_reference_documents": MAX_DOCUMENTS,
        "tool_calls_per_diagnosis": MAX_TOOL_CALLS,
        "tool_requests_per_diagnosis": MAX_TOOL_REQUESTS,
        "tool_argument_chars": MAX_ARGUMENT_CHARS,
        "tool_result_chars_for_model": MAX_RESULT_CHARS,
        "diagnostic_records_per_query": MAX_RECORDS,
        "diagnostic_evidence_per_finding": MAX_EVIDENCE,
        "diagnostic_time_range_seconds": int(MAX_TIME_RANGE.total_seconds()),
        "knowledge_results_per_query": field_maximum(KnowledgeQuery, "limit"),
        "incident_history_results": field_maximum(IncidentFilter, "limit"),
    }
