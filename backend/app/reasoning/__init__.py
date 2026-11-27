"""Diagnostic intelligence on top of the evidence the read-only tools collect.

Everything in this package is deterministic and read-only: specialist agents plan tool calls through the existing
ToolExecutor (same budget, allowlist and provenance), and the reasoning steps (Bayesian fault probabilities, evidence
calibration, contradictions, causal and temporal analysis, uncertainty, self-evaluation, explanation and planning) are
computed in code from evidence items. No step calls a model; the configured model, when there is one, still drives
the existing diagnosis agent and the reply composer.
"""
