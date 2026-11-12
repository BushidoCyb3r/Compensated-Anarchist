"""Credential redaction for tool output.

Security data is full of credentials: command lines with API keys, HTTP headers with bearer tokens, scripts with
passwords, private keys in files. Tool output reaches the model (off the network, for a hosted one) and is saved in
transcripts, the chat history, spill files, memories and reports, so one credential in one log line would otherwise
be copied everywhere. The tool executor passes every result through `Redactor.redact` first.

Each credential value is replaced with a placeholder such as `<redacted:bearer fp:3f9a1c2e7b>`. The fingerprint is
an HMAC with this installation's key (config/secrets/redaction.key), so the same value gets the same fingerprint in
every output (agents can still count distinct tokens and follow one across events), but it cannot be checked against
guessed passwords offline. An Elasticsearch API key also keeps its key id, which is not secret, so the analyst knows
which key to invalidate.

What it catches: the secret values in this installation's environment (config/.env), private key blocks, passwords
in URLs, Authorization headers and bare Bearer/ApiKey/Basic credentials, JWTs, common cloud and SaaS token formats,
`password=` / `api_key:` / `--token X` style pairs, and any patterns the site adds (redaction.patterns). What it
cannot: a credential with no recognizable shape (a password passed as a bare positional argument). Evidence files on
disk are never changed; only what reaches the model and the saved conversation is redacted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path
from typing import Any, Callable, Iterable

PLACEHOLDER = "<redacted"
_NOT_PLACEHOLDER = r"(?!<redacted)"

# environment variables whose values are this installation's own secrets
_SECRET_NAME = re.compile(r"(?i)(?:^|_)(?:KEY|TOKEN|SECRET|PASS|PASSWORD|PASSPHRASE|CREDENTIALS?)(?:$|_)")
_NOT_SECRET_NAME = re.compile(r"(?i)_(?:HEADER|URL|PATH|FILE|DIR|CONFIG|VERIFY|ENABLED|MODEL|CERT|BUNDLE|INDEX)$|"
                              r"CLIENT_KEY$")
_PATHLIKE = re.compile(r"^(?:[/~]|https?://|\$\{)")

_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]*?)PRIVATE KEY((?: BLOCK)?)-----.*?-----END \1PRIVATE KEY\2-----", re.S)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20}://)([^/\s:@'\"<>]{1,128}):" + _NOT_PLACEHOLDER
                           + r"([^/\s@'\"<>]{1,256})@")
_AUTH_HEADER = re.compile(r"(?i)\b((?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?\s*)"
                          r"(bearer|basic|apikey|token|digest|negotiate|ntlm|key|sharedaccesssignature)\s+"
                          + _NOT_PLACEHOLDER + r"([A-Za-z0-9._~+/=:-]{6,})")
_BARE_SCHEME = re.compile(r"(?i)\b(bearer|apikey)\s+" + _NOT_PLACEHOLDER + r"([A-Za-z0-9._~+/=-]{16,})")
_BARE_BASIC = re.compile(r"(?i)\b(basic)\s+([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_VENDOR = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    # sk-ant-..., sk-proj-/svcacct-/admin-..., or a long plain run; not SSH's sk-ecdsa-.../sk-ssh-... algorithm names
    ("ai-api-key", re.compile(r"\bsk-(?:ant-[A-Za-z0-9_-]{20,}|(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{40,})")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]
_PAIR_NAMES = (r"password|passwd|passphrase|secret|client[_-]?secret|secret[_-]?key|secret[_-]?access[_-]?key|"
               r"aws[_-]?secret[_-]?access[_-]?key|api[_-]?key|x-api-key|apikey|access[_-]?token|refresh[_-]?token|"
               r"auth[_-]?token|x-auth-token|session[_-]?secret|private[_-]?key|token|authorization")
_PAIR = re.compile(r"(?i)(?<![A-Za-z0-9_-])(" + _PAIR_NAMES + r")([\"']?\s*[:=]\s*[\"']?)" + _NOT_PLACEHOLDER
                   + r"(?!(?:true|false|null|none|yes|no|required|optional|\*+|bearer|basic|apikey|digest|negotiate|ntlm)"
                     r"(?![^\s\"'&,;<>{}\[\]]))"
                   + r"([^\s\"'&,;<>{}\[\]]{4,})")
# bare "pass" only as pass=... (query strings, command lines): "pass:" is common prose ("second pass: verify ...")
_PASS_EQ = re.compile(r"(?i)(?<![A-Za-z0-9_-])(pass)(=)" + _NOT_PLACEHOLDER + r"([^\s\"'&,;<>{}\[\]]{4,})")
_FLAG = re.compile(r"(?i)(?<![A-Za-z0-9_-])(--?(?:password|passwd|pass|passphrase|token|api-?key|secret|"
                   r"client-secret|auth-token|access-token))(\s+|=)" + _NOT_PLACEHOLDER + r"(?!-)([^\s\"']{4,})")


class Redactor:
    def __init__(self, key: bytes | None = None, enabled: bool = True, patterns: Iterable[str] = (),
                 env: Callable[[], dict[str, str]] | None = None):
        self.key = key or secrets.token_bytes(32)
        self.enabled = enabled
        self.extra = [re.compile(p) for p in patterns]
        self.env = env or (lambda: dict(os.environ))

    @classmethod
    def for_config(cls, cfg: Any) -> "Redactor":
        """This installation's redactor: its persistent key, `redaction:` in harness.yaml, the secrets in its
        environment (config/.env is loaded into it, and re-read while the dashboard runs)."""
        rc = (cfg.raw.get("redaction") or {}) if hasattr(cfg, "raw") else {}
        bad = []
        for p in rc.get("patterns") or []:
            try:
                re.compile(p)
            except re.error as e:
                bad.append(f"{p!r}: {e}")
        if bad:
            raise ValueError("redaction.patterns in harness.yaml: " + "; ".join(bad))
        return cls(load_key(Path(cfg.root) / "secrets" / "redaction.key"), rc.get("enabled", True) is not False,
                   rc.get("patterns") or [])

    def fingerprint(self, value: str) -> str:
        return hmac.new(self.key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:10]

    def _mark(self, kind: str, value: str) -> str:
        extra = ""
        if kind in ("apikey", "authorization-apikey", "bearer"):
            extra = _es_key_id(value)
        return f"<redacted:{kind}{f' id:{extra}' if extra else ''} fp:{self.fingerprint(value)}>"

    def own_secrets(self) -> list[tuple[str, str]]:
        """(variable name, value) for this installation's secrets in the environment, longest value first."""
        out = []
        for name, value in self.env().items():
            v = value.strip()
            if (len(v) >= 8 and _SECRET_NAME.search(name) and not _NOT_SECRET_NAME.search(name)
                    and not _PATHLIKE.match(v) and v.lower() not in ("true", "false", "changeme", "change-me")):
                out.append((name, v))
        return sorted(out, key=lambda x: -len(x[1]))

    def redact(self, text: str) -> tuple[str, int]:
        """(text with every credential value replaced, how many were replaced)."""
        if not self.enabled or not text:
            return text, 0
        n = 0

        def count(s: str, k: int) -> str:
            nonlocal n
            n += k
            return s

        for name, value in self.own_secrets():
            if value in text:
                text = count(text.replace(value, f"<redacted:{name} fp:{self.fingerprint(value)}>"), text.count(value))
        for rx in self.extra:
            text, k = rx.subn(lambda m: self._mark("site-pattern", m.group(0)), text)
            count(text, k)
        text, k = _PEM.subn(lambda m: self._mark("private-key", m.group(0)), text)
        count(text, k)
        text, k = _URL_USERINFO.subn(lambda m: f"{m.group(1)}{m.group(2)}:{self._mark('url-password', m.group(3))}@", text)
        count(text, k)
        text, k = _AUTH_HEADER.subn(lambda m: f"{m.group(1)}{m.group(2)} {self._mark(m.group(2).lower(), m.group(3))}", text)
        count(text, k)
        text, k = _BARE_SCHEME.subn(lambda m: f"{m.group(1)} {self._mark(m.group(1).lower(), m.group(2))}", text)
        count(text, k)

        def basic(m: re.Match[str]) -> str:
            nonlocal n
            if not _decodes_to_userpass(m.group(2)):
                return m.group(0)
            n += 1
            return f"{m.group(1)} {self._mark('basic', m.group(2))}"
        text = _BARE_BASIC.sub(basic, text)
        text, k = _JWT.subn(lambda m: self._mark("jwt", m.group(0)), text)
        count(text, k)
        for kind, rx in _VENDOR:
            text, k = rx.subn(lambda m, kind=kind: self._mark(kind, m.group(0)), text)
            count(text, k)
        text, k = _PAIR.subn(lambda m: f"{m.group(1)}{m.group(2)}{self._mark(m.group(1).lower(), m.group(3))}", text)
        count(text, k)
        text, k = _PASS_EQ.subn(lambda m: f"{m.group(1)}{m.group(2)}{self._mark('pass', m.group(3))}", text)
        count(text, k)
        text, k = _FLAG.subn(lambda m: f"{m.group(1)}{m.group(2)}{self._mark(m.group(1).lstrip('-').lower(), m.group(3))}",
                             text)
        count(text, k)
        return text, n


def load_key(path: Path) -> bytes:
    """The installation's fingerprint key (created once, mode 600), or a per-process key if it cannot be stored."""
    try:
        return bytes.fromhex(path.read_text().strip())
    except (OSError, ValueError):
        pass
    key = secrets.token_bytes(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key.hex())
    except FileExistsError:  # another process made it first: use theirs
        try:
            return bytes.fromhex(path.read_text().strip())
        except (OSError, ValueError):
            return key
    except OSError:
        return key
    return key


def _decode(value: str) -> str:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def _es_key_id(value: str) -> str:
    """An Elasticsearch API key is base64("<id>:<secret>"): its id is not secret and names the key to invalidate."""
    m = re.fullmatch(r"([A-Za-z0-9_-]{16,32}):[A-Za-z0-9_-]{16,}", _decode(value))
    return m.group(1) if m else ""


def _decodes_to_userpass(value: str) -> bool:
    d = _decode(value)
    return bool(d) and ":" in d and d.isprintable()


HARNESS_NOTE = ("[harness: {n} credential value(s) in this output were replaced with <redacted:...> placeholders before "
                "you saw them. The same fp means the same value. A credential appearing in data is worth reporting "
                "(where, and which kind or key id); never try to recover the value.]")
