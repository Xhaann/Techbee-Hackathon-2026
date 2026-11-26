from app.diagnostics import ToolResult, ToolStatus


def ok(result: ToolResult) -> ToolResult:
    assert result.status == ToolStatus.SUCCESS, result.error
    assert result.error is None
    return result


def failed(result: ToolResult, code: str) -> ToolResult:
    assert result.status == ToolStatus.ERROR
    assert result.data is None
    assert result.error is not None and result.error.code == code, result.error
    return result


def codes(result: ToolResult, kind: str | None = None) -> list[str]:
    return [finding.code for finding in result.findings if kind is None or finding.kind.value == kind]
