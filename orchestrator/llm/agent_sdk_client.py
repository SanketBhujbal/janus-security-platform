"""LLM client backed by Claude Agent SDK.

Uses the user's Claude Code login for authentication -- no separate
ANTHROPIC_API_KEY required. The Agent SDK invokes the `claude` CLI under
the hood, so the user just needs to be logged in (`claude /login`).

We adapt the SDK's async streaming API to our sync `LLMClient.complete`
contract. The brain runs in a worker thread (see `webapp.manager.ScanRunner`),
so `asyncio.run()` works there because each thread has its own event loop
context.

Tool use is explicitly disabled -- we only want pure text completion that
returns JSON. `max_turns=1` guarantees a single response.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from .claude_client import DEFAULT_MAX_TOKENS, LLMClient, LLMResponse

try:
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        ResultMessage,
        TextBlock,
        query,
    )

    _SDK_AVAILABLE = True
except ImportError:  # pragma: no cover -- environments without the SDK installed
    _SDK_AVAILABLE = False


log = logging.getLogger("security_brain.llm.agent_sdk")


DEFAULT_MODEL = os.environ.get("CLAUDE_AGENT_MODEL")  # None -> SDK / Claude Code default


class ClaudeAgentSDKClient(LLMClient):
    # `model=None` lets the SDK / claude CLI pick the default (whatever the
    # user's Claude Code login is using). Override with CLAUDE_AGENT_MODEL env
    # var or constructor arg if you want a specific model.

    def __init__(self, model: str | None = None) -> None:
        if not _SDK_AVAILABLE:
            raise RuntimeError(
                "claude-agent-sdk not installed. pip install claude-agent-sdk"
            )
        self.model = model or DEFAULT_MODEL

    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
    ) -> LLMResponse:
        # Note: the Agent SDK doesn't expose temperature or max_tokens to us
        # directly -- those are governed by Claude Code's defaults. The kwargs
        # are kept for interface compatibility with `ClaudeClient`.
        return asyncio.run(self._complete_async(system, user))

    async def _complete_async(self, system: str, user: str) -> LLMResponse:
        options = ClaudeAgentOptions(
            # Bigger prompts (healer with full snippet + explanation) can spill
            # into multiple internal assistant turns. max_turns=1 caused
            # "Reached maximum number of turns (1)" errors. 5 is plenty for a
            # one-shot completion that returns JSON.
            system_prompt=system,
            max_turns=5,
            allowed_tools=[],            # pure text completion, no tools
            permission_mode="bypassPermissions",
            model=self.model,
        )
        chunks: list[str] = []
        usage: dict[str, Any] | None = None
        is_error = False
        try:
            async for msg in query(prompt=user, options=options):
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock):
                            chunks.append(block.text)
                    if msg.error:
                        is_error = True
                        log.error("agent sdk assistant error: %s", msg.error)
                elif isinstance(msg, ResultMessage):
                    usage = msg.usage
                    if msg.is_error:
                        is_error = True
                        log.error("agent sdk result error: %s", msg.errors)
        except Exception:
            log.exception("agent sdk query failed")
            raise

        text = "".join(chunks).strip()
        if is_error and not text:
            raise RuntimeError("claude-agent-sdk: query returned an error with no text")

        return LLMResponse(
            text=text,
            raw={"usage": usage} if usage else {},
            input_tokens=int((usage or {}).get("input_tokens") or 0),
            output_tokens=int((usage or {}).get("output_tokens") or 0),
        )
