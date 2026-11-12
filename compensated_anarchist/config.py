"""Configuration loading with ${ENV_VAR} / ${ENV_VAR:-default} expansion.

Secrets never live in YAML: reference them as ${VAR} and export them in the environment
(or load them from your vault / keyring before launching).
"""

from __future__ import annotations

import importlib.util
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


# ---- config/.env --------------------------------------------------------------------------------------
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def parse_env_file(path: Path) -> dict[str, str]:
    """KEY=value lines as `source` in bash reads them for plain files: '# ...' comment lines, optional `export`,
    "quoted" or 'quoted' values, an unquoted value ends at whitespace (so `KEY=   # note` is empty). No $expansion."""
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _ENV_LINE.match(line)
        if not m:
            continue
        key, v = m.group(1), m.group(2)
        if v[:1] in ("'", '"'):
            end = v.find(v[0], 1)
            v = v[1:end] if end > 0 else v[1:]
        else:
            v = v.split(None, 1)[0] if v and not v[0].isspace() else ""
        out[key] = v
    return out


@dataclass
class EnvFile:
    """config/.env, read by the harness itself (no `source` needed) and re-read while it runs, so a key added for a
    new model works without a restart. The values never leave the process environment: nothing logs or shows them."""
    path: Path
    values: dict[str, str] = field(default_factory=dict)  # as last read from the file
    sig: tuple = ()

    def load(self) -> None:
        """At startup: set the variables the process does not have yet. The launching shell's values win."""
        self.sig = _files_sig([self.path])
        self.values = self._read()
        for k, v in self.values.items():
            os.environ.setdefault(k, v)

    def refresh(self) -> list[str]:
        """Apply edits made since the last read: new or changed variables are set, removed ones unset (unless the
        process got a different value elsewhere). Returns the names that changed; never their values."""
        sig = _files_sig([self.path])
        if sig == self.sig:
            return []
        self.sig = sig
        new = self._read()
        changed = []
        for k, v in new.items():
            if self.values.get(k) != v:
                os.environ[k] = v
                changed.append(k)
        for k, old in self.values.items():
            if k not in new and os.environ.get(k) == old:
                del os.environ[k]
                changed.append(k)
        self.values = new
        return changed

    def _read(self) -> dict[str, str]:
        try:
            return parse_env_file(self.path) if self.path.is_file() else {}
        except (OSError, UnicodeDecodeError):
            return dict(self.values)  # unreadable mid-edit: keep what we had


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
    stream: bool = True  # stream tokens to the UI; openai_compat falls back to non-streaming if the server refuses
    label: str = ""  # name shown in the dashboard's model picker
    group: str = ""  # picker section: GenAI | Claude | ChatGPT | Local | ...
    max_tokens_param: str = "max_tokens"  # openai_compat: "max_completion_tokens" for OpenAI's own API

    def problem(self) -> str:
        """Why this profile cannot work yet ('' when it looks usable). Reachability is not checked."""
        if "CHANGE-ME" in f"{self.base_url} {self.model}":
            return "fill in its CHANGE-ME values (in config/models.yaml, or the variables it names in config/.env)"
        if self.provider == "openai_compat" and not self.base_url:
            return "no base_url"
        if self.provider == "anthropic":
            if importlib.util.find_spec("anthropic") is None:
                return "the Anthropic SDK is not installed: pip install 'compensated-anarchist[anthropic]'"
            if not self.api_key:
                return "no API key: set ANTHROPIC_API_KEY in config/.env"
        if "api.openai.com" in self.base_url and not self.api_key:
            return "no API key: set OPENAI_API_KEY in config/.env"
        return ""

    def public(self) -> dict[str, Any]:
        why = self.problem()
        return {"name": self.name, "label": self.label or self.name, "group": self.group or "Other",
                "provider": self.provider, "model": self.model, "ready": not why, "problem": why}


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
    history_db: Path = Path("history.db")
    forensics_dir: Path = Path("forensics")  # per-case drop folders: <forensics_dir>/<case-id>/ (an evidence root)
    attack_paths: list[Path] = field(default_factory=list)  # MITRE ATT&CK STIX bundles (enterprise-attack.json, ...)
    model_files: list[Path] = field(default_factory=list)  # models.yaml, models.local.yaml (merged in that order)
    env_file: EnvFile | None = None  # config/.env, re-read with the model files
    config_path: Path | None = None  # harness.yaml (its legacy inline models: are re-read too)
    models_error: str = ""  # why the last edit of the model files was not applied ('' = fine)
    _models_sig: tuple = ()
    skills: dict[str, Any] = field(default_factory=dict)
    orchestration: dict[str, Any] = field(default_factory=dict)
    learning: dict[str, Any] = field(default_factory=dict)
    budgets: dict[str, Any] = field(default_factory=dict)
    tool_specs_dir: Path = Path("tool_specs")

    def reload_models(self) -> bool:
        """Re-read config/.env and the model files when they changed on disk (the dashboard calls this; no restart).
        A broken edit keeps the previous profiles and is reported in models_error. True when profiles changed."""
        env_changed = self.env_file.refresh() if self.env_file else []
        sig = _files_sig(self._model_sources())
        if sig == self._models_sig and not env_changed:
            return False
        self._models_sig = sig
        try:
            raw = load_yaml(self.config_path) if self.config_path else self.raw  # re-expanded with the new env
            models, _ = load_models(raw, self.model_files)
        except (ValueError, TypeError, OSError, yaml.YAMLError) as e:
            self.models_error = str(e)
            return False
        self.models, self.models_error = models, ""
        return True

    def _model_sources(self) -> list[Path]:
        return ([self.config_path] if self.config_path else []) + self.model_files

    def model(self, name: str | None = None) -> ModelProfile:
        key = name or self.default_model
        if key not in self.models:
            raise KeyError(f"unknown model profile '{key}'. Known: {', '.join(self.models)}")
        return self.models[key]


def _files_sig(files: list[Path]) -> tuple:
    return tuple((str(f), f.stat().st_mtime_ns if f.exists() else None) for f in files)


def load_models(raw: dict[str, Any], files: list[Path]) -> tuple[dict[str, ModelProfile], str]:
    """Model profiles from harness.yaml's `models:` (legacy), then each file in order. A later file overrides
    fields of an earlier profile with the same name; `enabled: false` drops a profile. Returns (profiles, the last
    default_model set by a file)."""
    specs: dict[str, dict[str, Any]] = {}
    default = ""

    def merge(src: Any, where: str) -> None:
        nonlocal default
        if not isinstance(src, dict):
            raise ValueError(f"{where}: expected a mapping at the top level")
        block = src.get("models") or {}
        if not isinstance(block, dict):
            raise ValueError(f"{where}: 'models' must be a mapping of profile name -> fields")
        for name, spec in block.items():
            if not isinstance(spec, dict):
                raise ValueError(f"{where}: model profile '{name}' must be a mapping of fields")
            specs[str(name)] = {**specs.get(str(name), {}), **spec}
        if src.get("default_model"):
            default = str(src["default_model"])

    merge({"models": raw.get("models")}, "harness.yaml")
    for f in files:
        if f.exists():
            merge(load_yaml(f), f.name)
    allowed = set(ModelProfile.__dataclass_fields__) - {"name"}
    models: dict[str, ModelProfile] = {}
    for name, spec in specs.items():
        spec = dict(spec)
        enabled = spec.pop("enabled", True)
        unknown = set(spec) - allowed
        if unknown:
            raise ValueError(f"model profile '{name}': unknown keys {sorted(unknown)}")
        if enabled is False or str(enabled).strip().lower() in ("false", "no", "off", "0"):
            continue
        models[name] = ModelProfile(name=name, **spec)
    if not models:
        raise ValueError("no model profiles: define them under 'models:' in config/models.yaml")
    return models, default


def load_config(path: str | Path) -> HarnessConfig:
    path = Path(path).resolve()
    env_file = EnvFile(Path(os.environ.get("CA_ENV_FILE") or path.parent / ".env").expanduser().resolve())
    env_file.load()  # before harness.yaml, whose ${VARIABLES} it fills in
    raw = load_yaml(path)
    root = path.parent

    def rel(p: str) -> Path:
        q = Path(os.path.expanduser(p))
        return q if q.is_absolute() else (root / q).resolve()

    model_files: list[Path] = []
    if raw.get("models_file", "models.yaml"):
        mf = rel(str(raw.get("models_file", "models.yaml")))
        model_files = [mf, mf.with_name(f"{mf.stem}.local{mf.suffix}")]
    models, file_default = load_models(raw, model_files)

    h = raw.get("harness") or {}
    default_model = os.environ.get("CA_MODEL") or h.get("default_model") or file_default or next(iter(models))
    forensics_dir = rel(h.get("forensics_dir", "../forensics"))
    evidence_roots = [rel(p) for p in h.get("evidence_roots", ["../evidence"])]
    if forensics_dir not in evidence_roots:  # case drop folders are always readable by the forensic tools
        evidence_roots.append(forensics_dir)
    attack_cfg = raw.get("attack") or {}
    attack_env = [x.strip() for x in os.environ.get("ATTACK_STIX", "").split(",") if x.strip()]
    attack_paths = [rel(p) for p in (attack_env or attack_cfg.get("stix") or ["../data/attack/enterprise-attack.json"])]
    return HarnessConfig(
        raw=raw,
        root=root,
        models=models,
        default_model=default_model,
        cases_dir=rel(h.get("cases_dir", "../cases")),
        memory_db=rel((raw.get("memory") or {}).get("db_path", "../memory/dco_memory.db")),
        evidence_roots=evidence_roots,
        forensics_dir=forensics_dir,
        attack_paths=attack_paths,
        model_files=model_files,
        env_file=env_file,
        config_path=path,
        _models_sig=_files_sig([path, *model_files]),
        roe_path=rel(h.get("roe", "roe.yaml")),
        operator=os.environ.get("CA_OPERATOR") or h.get("operator") or os.environ.get("USER", "unknown"),
        max_steps=int(h.get("max_steps", 40)),
        max_tool_result_chars=int(h.get("max_tool_result_chars", 12000)),
        mcp_servers=raw.get("mcp_servers") or {},
        forensics=raw.get("forensics") or {},
        memory=raw.get("memory") or {},
        experts=raw.get("experts") or {},
        history_db=rel((raw.get("history") or {}).get("db_path") or str(Path(h.get("cases_dir", "../cases")) / "_history.db")),
        skills=raw.get("skills") or {},
        orchestration=raw.get("orchestration") or {},
        learning=raw.get("learning") or {},
        budgets=raw.get("budgets") or {},
        tool_specs_dir=rel((raw.get("tool_onboarding") or {}).get("specs_dir", "../tool_specs")),
    )
