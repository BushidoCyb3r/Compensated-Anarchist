from ..config import ModelProfile
from .base import LLMBackend, LLMResponse, ToolCall, ToolSpec


def make_backend(profile: ModelProfile) -> LLMBackend:
    if profile.provider == "openai_compat":
        from .openai_compat import OpenAICompatBackend

        return OpenAICompatBackend(profile)
    if profile.provider == "anthropic":
        from .anthropic_backend import AnthropicBackend

        return AnthropicBackend(profile)
    raise ValueError(f"unknown provider '{profile.provider}' (use openai_compat or anthropic)")


__all__ = ["make_backend", "LLMBackend", "LLMResponse", "ToolCall", "ToolSpec"]
