from typing import Any

from ..config import ModelProfile
from .base import DeltaFn, LLMBackend, LLMResponse, ToolCall, ToolSpec


class ModelNotReady(RuntimeError):
    """The chosen model profile is not set up yet (a CHANGE-ME value, a missing key, a missing SDK)."""


class NotReadyBackend:
    """Stands in for a profile that cannot work yet, so every run on it (dashboard, chat, run, an expert routed to
    it) stops at the first model call with what to set up, instead of a connection error. Nothing falls back to
    another model by itself: that could send the case's data to a hosted model nobody chose."""

    def __init__(self, profile: ModelProfile, why: str):
        self.profile, self.profile_name, self.context_tokens = profile, profile.name, profile.context_tokens
        self.why = why

    async def chat(self, messages: list[dict[str, Any]], tools: list[ToolSpec], on_delta: DeltaFn | None = None) -> LLMResponse:
        raise ModelNotReady(f"the model '{self.profile_name}' is not set up yet: {self.why}. Choose a ready model in the "
                            "dashboard's model picker (or --model / CA_MODEL), or set this one up (SETUP.md section 1).")

    async def aclose(self) -> None:
        return None


def make_backend(profile: ModelProfile) -> LLMBackend:
    if why := profile.problem():
        return NotReadyBackend(profile, why)
    if profile.provider == "openai_compat":
        from .openai_compat import OpenAICompatBackend

        return OpenAICompatBackend(profile)
    if profile.provider == "anthropic":
        from .anthropic_backend import AnthropicBackend

        return AnthropicBackend(profile)
    raise ValueError(f"unknown provider '{profile.provider}' (use openai_compat or anthropic)")


__all__ = ["make_backend", "DeltaFn", "LLMBackend", "LLMResponse", "ModelNotReady", "NotReadyBackend", "ToolCall",
           "ToolSpec"]
