"""Google ADK + Vertex AI (`location=global`) Model Builder, Runner Executor & Telemetry Tracker (`telemetry.py`).

Captures authentic runtime telemetry from Google ADK `Runner` executions:
- `model_version` reported by Vertex AI (`LlmResponse.model_version`)
- Token consumption (`input_tokens`, `output_tokens`, `thought_tokens`, `total_tokens`)
- Tool invocation trace (`agent`, `tool`, `args`, `duration_ms`, `status`)
- Invoked ADK agent roster and end-to-end wall-clock latency
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import functools
import inspect
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Callable, Coroutine, Dict, List, Optional, Type, TypeVar

from google.adk.agents import Agent
from google.adk.agents.run_config import RunConfig
from google.adk.models.google_llm import Gemini
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from pydantic import BaseModel

from backend.config import DEFAULT_VERTEX_LOCATION, resolve_vertex_model, settings
from backend.models.findings import (
    AdkExecutionTelemetry,
    AdkTokenUsage,
    AdkToolCallRecord,
)

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

DEFAULT_AGENT_TIMEOUT_SECONDS = 180.0
DEFAULT_AGENT_MAX_LLM_CALLS = 20


class AgentExecutionTimeoutError(TimeoutError):
    """Raised when an ADK agent execution exceeds its configured wall-clock timeout."""


def make_async_adk_tool(sync_fn: Callable[..., Any]) -> Callable[..., Coroutine[Any, Any, Any]]:
    """Wraps a synchronous tool function in an `async def` ADK tool delegating execution to `asyncio.to_thread`."""
    if inspect.iscoroutinefunction(sync_fn):
        return sync_fn  # type: ignore[return-value]

    @functools.wraps(sync_fn)
    async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(sync_fn, *args, **kwargs)

    # Preserve exact parameter signature so ADK FunctionTool schema generation sees identical params
    _async_wrapper.__signature__ = inspect.signature(sync_fn)  # type: ignore[attr-defined]
    return _async_wrapper


def build_vertex_gemini_model(model_name: Optional[str] = None) -> Gemini:
    """Builds a Google ADK `Gemini` model bound to Vertex AI (`location='global'`)."""
    settings.ensure_vertex_environment()
    resolved = resolve_vertex_model(model_name or settings.vertex_model_id)
    return Gemini(
        model=resolved,
        client_kwargs={
            "location": DEFAULT_VERTEX_LOCATION,
            "http_options": types.HttpOptions(timeout=180_000),
        },
    )


def build_generate_content_config(model_name: Optional[str] = None) -> types.GenerateContentConfig:
    """Builds `GenerateContentConfig` for `gemini-3.1-pro-preview-customtools` on Vertex AI (`location=global`)."""
    resolve_vertex_model(model_name or settings.vertex_model_id)
    return types.GenerateContentConfig(
        max_output_tokens=32768,
        thinking_config=types.ThinkingConfig(
            thinking_level=types.ThinkingLevel.MEDIUM,
            include_thoughts=True,
        ),
    )


def _sanitize_tool_args(raw_args: Any) -> Dict[str, Any]:
    if not isinstance(raw_args, dict):
        return {}
    clean: Dict[str, Any] = {}
    for k, v in raw_args.items():
        if isinstance(v, (int, float, bool)) or v is None:
            clean[str(k)] = v
        else:
            s = str(v)
            clean[str(k)] = s if len(s) <= 240 else (s[:237] + "...")
    return clean


class AdkTurnTracker:
    """Callback-driven telemetry collector for Google ADK `Agent` and `Runner` executions."""

    def __init__(self, requested_model: str) -> None:
        self.requested_model = resolve_vertex_model(requested_model)
        self.model_versions: List[str] = []
        self.agents_invoked: List[str] = []
        self.llm_steps: int = 0
        self.input_tokens: int = 0
        self.output_tokens: int = 0
        self.thought_tokens: int = 0
        self.total_tokens: int = 0
        self.tool_calls: List[AdkToolCallRecord] = []
        self._pending_tool_starts: Dict[str, float] = {}
        self._started_at: float = time.monotonic()

    def _record_agent(self, agent_name: str) -> None:
        if agent_name and agent_name not in self.agents_invoked:
            self.agents_invoked.append(agent_name)

    def after_model_callback(self, *args: Any, **kwargs: Any) -> None:
        callback_context = kwargs.get("callback_context") or (args[0] if len(args) > 0 else None)
        llm_response = kwargs.get("llm_response") or (args[1] if len(args) > 1 else None)
        agent_name = getattr(callback_context, "agent_name", "") or "adk_agent"
        self._record_agent(agent_name)
        if llm_response is None:
            return

        self.llm_steps += 1
        mv = getattr(llm_response, "model_version", None)
        if mv and mv not in self.model_versions:
            self.model_versions.append(str(mv))

        usage = getattr(llm_response, "usage_metadata", None)
        if usage is not None:
            p_tok = int(getattr(usage, "prompt_token_count", 0) or 0)
            c_tok = int(getattr(usage, "candidates_token_count", 0) or 0)
            th_tok = int(getattr(usage, "thoughts_token_count", 0) or 0)
            tot_tok = int(getattr(usage, "total_token_count", 0) or (p_tok + c_tok + th_tok))
            self.input_tokens += p_tok
            self.output_tokens += c_tok
            self.thought_tokens += th_tok
            self.total_tokens += tot_tok

    def before_tool_callback(self, *args: Any, **kwargs: Any) -> None:
        tool = kwargs.get("tool") or (args[0] if len(args) > 0 else None)
        tool_context = kwargs.get("tool_context") or (args[2] if len(args) > 2 else None)
        tool_name = getattr(tool, "name", None) or str(tool)
        agent_name = getattr(tool_context, "agent_name", "") or "adk_agent"
        self._record_agent(agent_name)
        call_key = f"{agent_name}:{tool_name}:{getattr(tool_context, 'function_call_id', '')}"
        self._pending_tool_starts[call_key] = time.monotonic()

    def after_tool_callback(self, *args: Any, **kwargs: Any) -> None:
        tool = kwargs.get("tool") or (args[0] if len(args) > 0 else None)
        tool_args = kwargs.get("args") if "args" in kwargs else (args[1] if len(args) > 1 else {})
        tool_context = kwargs.get("tool_context") or (args[2] if len(args) > 2 else None)
        tool_response = kwargs.get("tool_response") if "tool_response" in kwargs else (args[3] if len(args) > 3 else None)

        tool_name = getattr(tool, "name", None) or str(tool)
        agent_name = getattr(tool_context, "agent_name", "") or "adk_agent"
        call_key = f"{agent_name}:{tool_name}:{getattr(tool_context, 'function_call_id', '')}"
        t0 = self._pending_tool_starts.pop(call_key, self._started_at)
        dur_ms = round((time.monotonic() - t0) * 1000.0, 1)

        status = "ok"
        if isinstance(tool_response, dict) and tool_response.get("error"):
            status = "error"

        self.tool_calls.append(
            AdkToolCallRecord(
                agent=agent_name,
                tool=tool_name,
                args=_sanitize_tool_args(tool_args),
                duration_ms=dur_ms,
                status=status,
            )
        )

    def to_telemetry(self) -> AdkExecutionTelemetry:
        elapsed_ms = round((time.monotonic() - self._started_at) * 1000.0, 1)
        primary_mv = self.model_versions[-1] if self.model_versions else self.requested_model
        return AdkExecutionTelemetry(
            requested_model=self.requested_model,
            model_version=primary_mv,
            model_versions=list(self.model_versions) or [self.requested_model],
            location=DEFAULT_VERTEX_LOCATION,
            agents_invoked=list(self.agents_invoked),
            llm_steps=self.llm_steps,
            tokens=AdkTokenUsage(
                input_tokens=self.input_tokens,
                output_tokens=self.output_tokens,
                thought_tokens=self.thought_tokens,
                total_tokens=self.total_tokens,
            ),
            tool_calls=list(self.tool_calls),
            latency_ms=elapsed_ms,
        )


def merge_adk_telemetries(
    requested_model: str,
    items: List[AdkExecutionTelemetry],
    wall_latency_ms: float,
) -> AdkExecutionTelemetry:
    """Merges telemetry across parallel and sequential ADK specialist executions."""
    resolved = resolve_vertex_model(requested_model)
    model_versions: List[str] = []
    agents_invoked: List[str] = []
    tool_calls: List[AdkToolCallRecord] = []
    llm_steps = 0
    in_tok = 0
    out_tok = 0
    th_tok = 0
    tot_tok = 0
    ungrounded_total = 0
    dropped_by_agent: Dict[str, int] = {}

    for item in items:
        llm_steps += item.llm_steps
        in_tok += item.tokens.input_tokens
        out_tok += item.tokens.output_tokens
        th_tok += item.tokens.thought_tokens
        tot_tok += item.tokens.total_tokens
        ungrounded_total += int(getattr(item, "ungrounded_findings_dropped", 0) or 0)
        for ag_name, cnt in (getattr(item, "ungrounded_items_dropped_by_agent", None) or {}).items():
            dropped_by_agent[ag_name] = dropped_by_agent.get(ag_name, 0) + int(cnt or 0)
        for mv in item.model_versions:
            if mv and mv not in model_versions:
                model_versions.append(mv)
        if item.model_version and item.model_version not in model_versions:
            model_versions.append(item.model_version)
        for ag in item.agents_invoked:
            if ag and ag not in agents_invoked:
                agents_invoked.append(ag)
        tool_calls.extend(item.tool_calls)

    primary_mv = model_versions[-1] if model_versions else resolved
    return AdkExecutionTelemetry(
        requested_model=resolved,
        model_version=primary_mv,
        model_versions=model_versions or [resolved],
        location=DEFAULT_VERTEX_LOCATION,
        agents_invoked=agents_invoked,
        llm_steps=llm_steps,
        tokens=AdkTokenUsage(
            input_tokens=in_tok,
            output_tokens=out_tok,
            thought_tokens=th_tok,
            total_tokens=tot_tok,
        ),
        tool_calls=tool_calls,
        latency_ms=round(wall_latency_ms, 1),
        ungrounded_findings_dropped=ungrounded_total,
        ungrounded_items_dropped_by_agent=dropped_by_agent,
    )


async def execute_adk_agent(
    agent: Agent,
    prompt: str,
    *,
    session_service: Optional[InMemorySessionService] = None,
    app_name: str = "agentic_iam_accelerator",
    user_id: str = "iam-orchestrator",
    session_id: Optional[str] = None,
    timeout_seconds: Optional[float] = None,
    max_llm_calls: Optional[int] = None,
) -> str:
    """Executes a Google ADK `Agent` via `Runner` with strict wall-clock timeout and LLM-call cap."""
    eff_timeout = float(
        timeout_seconds
        if timeout_seconds is not None
        else float(os.getenv("IAM_AGENT_TIMEOUT_SECONDS", str(DEFAULT_AGENT_TIMEOUT_SECONDS)))
    )
    eff_max_calls = max(
        1,
        int(
            max_llm_calls
            if max_llm_calls is not None
            else int(os.getenv("IAM_AGENT_MAX_LLM_CALLS", str(DEFAULT_AGENT_MAX_LLM_CALLS)))
        ),
    )

    svc = session_service or InMemorySessionService()
    sid = session_id or f"adk-{uuid.uuid4().hex[:10]}"
    existing = await svc.get_session(app_name=app_name, user_id=user_id, session_id=sid)
    if existing is None:
        await svc.create_session(app_name=app_name, user_id=user_id, session_id=sid)

    runner = Runner(agent=agent, app_name=app_name, session_service=svc)
    msg = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
    run_cfg = RunConfig(max_llm_calls=eff_max_calls)

    async def _collect_events() -> str:
        final_chunks: List[str] = []
        fallback_chunks: List[str] = []
        async for event in runner.run_async(
            user_id=user_id,
            session_id=sid,
            new_message=msg,
            run_config=run_cfg,
        ):
            if event.content and event.content.parts:
                text_parts = [
                    p.text
                    for p in event.content.parts
                    if getattr(p, "text", None) and not getattr(p, "thought", False)
                ]
                if text_parts:
                    if event.is_final_response():
                        final_chunks.extend(text_parts)
                    else:
                        fallback_chunks.extend(text_parts)

        output = "\n".join(final_chunks).strip() or "\n".join(fallback_chunks[-1:]).strip()
        if not output:
            raise RuntimeError(
                f"Google ADK agent '{getattr(agent, 'name', 'adk_agent')}' returned an empty response from Vertex AI ({DEFAULT_VERTEX_LOCATION})."
            )
        return output

    try:
        return await asyncio.wait_for(_collect_events(), timeout=eff_timeout)
    except asyncio.TimeoutError as exc:
        agent_name = getattr(agent, "name", "adk_agent")
        logger.warning("ADK agent '%s' timed out after %.1fs", agent_name, eff_timeout)
        raise AgentExecutionTimeoutError(
            f"Google ADK agent '{agent_name}' exceeded the {eff_timeout:.0f}s execution timeout. "
            f"Narrow the assessment scope or retry."
        ) from exc


def parse_structured_adk_output(raw_text: str, schema_cls: Type[T]) -> T:
    """Parses a Pydantic structured output returned by an ADK agent."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return schema_cls.model_validate_json(cleaned)
    except Exception:
        # Locate outermost JSON object if leading commentary was emitted
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end > start:
            return schema_cls.model_validate_json(cleaned[start : end + 1])
        raise


def run_async_from_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Runs an async ADK coroutine safely from synchronous contexts while propagating contextvars."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    ctx = contextvars.copy_context()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(ctx.run, asyncio.run, coro)
        return future.result()
