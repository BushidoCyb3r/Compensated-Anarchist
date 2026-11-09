"""Configuration loading with ${ENV_VAR} / ${ENV_VAR:-default} expansion.

Secrets never live in YAML: reference them as ${VAR} and export them in the environment
(or load them from your vault / keyring before launching).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def load_yaml(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return _expand(yaml.safe_load(fh) or {})


@dataclass
class ModelProfile:
    name: str
    provider: str  # "openai_compat" | "anthropic"
    model: str
    base_url: str = ""
    api_key: str = ""
    api_key_header: str = "Authorization"  # "Authorization" -> "Bearer <key>"; anything else -> raw key
    extra_headers: dict[str, str] = field(default_factory=dict)
    ca_bundle: str = ""  # DoD root CA bundle path, or "" for system default
    client_cert: str = ""  # PKI client cert (PEM) for mTLS gateways
    client_key: str = ""
    verify_tls: bool = True
    tool_mode: str = "native"  # "native" (function calling) | "text" (<tool_call> JSON in content)
    context_tokens: int = 32000  # used to decide when to compact history
    max_output_tokens: int = 4096
    timeout_s: float = 300.0
    extra_body: dict[str, Any] = field(default_factory=dict)  # provider-specific knobs (temperature, etc.)
    effort: str = "high"  # anthropic only


@dataclass
class HarnessConfig:
    raw: dict[str, Any]
    root: Path
    models: dict[str, ModelProfile]
    default_model: str
    cases_dir: Path
    memory_db: Path
    evidence_roots: list[Path]
    roe_path: Path
    operator: str
    max_steps: int
    max_tool_result_chars: int
    mcp_servers: dict[str, dict[str, Any]]
    forensics: dict[str, Any]
    memory: dict[str, Any]
    experts: dict[str, Any]

    def model(self, name: str | None = None) -> ModelProfile:
        key = name or self.default_model
        if key not in self.models:
            raise KeyError(f"unknown model profile '{key}'. Known: {', '.join(self.models)}")
        return self.models[key]


def load_config(path: str | Path) -> HarnessConfig:
    path = Path(path).resolve()
    raw = load_yaml(path)
    root = path.parent

    def rel(p: str) -> Path:
        q = Path(os.path.expanduser(p))
        return q if q.is_absolute() else (root / q).resolve()

    models: dict[str, ModelProfile] = {}
    for name, spec in (raw.get("models") or {}).items():
        allowed = set(ModelProfile.__dataclass_fields__)
        unknown = set(spec) - allowed
        if unknown:
            raise ValueError(f"model profile '{name}': unknown keys {sorted(unknown)}")
        models[name] = ModelProfile(name=name, **spec)
    if not models:
        raise ValueError("config must define at least one model profile under 'models:'")

    h = raw.get("harness") or {}
    default_model = os.environ.get("CA_MODEL") or h.get("default_model") or next(iter(models))
    return HarnessConfig(
        raw=raw,
        root=root,
        models=models,
        default_model=default_model,
        cases_dir=rel(h.get("cases_dir", "../cases")),
        memory_db=rel((raw.get("memory") or {}).get("db_path", "../memory/dco_memory.db")),
        evidence_roots=[rel(p) for p in h.get("evidence_roots", ["../evidence"])],
        roe_path=rel(h.get("roe", "roe.yaml")),
        operator=os.environ.get("CA_OPERATOR") or h.get("operator") or os.environ.get("USER", "unknown"),
        max_steps=int(h.get("max_steps", 40)),
        max_tool_result_chars=int(h.get("max_tool_result_chars", 12000)),
        mcp_servers=raw.get("mcp_servers") or {},
        forensics=raw.get("forensics") or {},
        memory=raw.get("memory") or {},
        experts=raw.get("experts") or {},
    )
