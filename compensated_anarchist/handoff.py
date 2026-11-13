"""How agents hand work to each other without the lead re-typing it, or carrying it on every model call.

Reports. A subagent's report reaches the lead in full, so the lead checks it and decides with all of it in view.
Once the lead has made `orchestration.report_full_calls` more model calls, the report shrinks in the lead's context
to its bottom line, key facts, open questions and recommended tasks, plus every identifier its details mention (IPs,
hashes, client ids, ATT&CK ids, times, case ids...), so the lead still knows those values exist. The full report
stays in the conversation, and `case_get(["SA-003.2"])` shows it again.

References. The lead passes case records (FIN-, IOC-, TIM-, EVI-, NOT-, STA-) and earlier reports (SA-003.2) to a
subagent by id (`refs`). The harness copies them into the brief exactly, so no value is re-typed or mistyped. Agents
wrote them from tool output, so they reach the subagent as untrusted data, like tool output.

Outputs. A tool result too long for one message is saved in the case's artifacts folder. Any agent with the case tools
pages or searches it with `case_read_artifact`, so raw output never has to pass through the lead.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

SHORT_MARK = "[shortened]"
MIN_SAVING = 600          # chars a shortened report must save; a short report stays as it is
SHORT_SUMMARY_CHARS = 1200  # a free-text answer (no submit_report) is all summary: its start stays, the rest is hidden
MAX_IDENTIFIERS = 60
MAX_TIMES = 12            # timestamps are many in a long report; the first ones are enough to know there are more
RECORD_CHARS = 1500       # one case record copied into a brief
REPORT_DETAILS_CHARS = 4000  # the details of one report copied into a brief
REFS_CHARS = 12000        # all records copied into one brief
MAX_REFS = 30
FIND_MAX_BYTES = 256 * 1024 * 1024  # case_read_artifact's find reads at most this much of one file

# Case record ids are the first three letters of the case.json list they live in, then a number (case.Case._append).
RECORD_LISTS = {"FIN": "findings", "IOC": "iocs", "TIM": "timeline", "EVI": "evidence", "NOT": "notes", "STA": "statements"}
RECORD_KIND = {"FIN": "finding", "IOC": "IOC", "TIM": "timeline event", "EVI": "evidence", "NOT": "note",
               "STA": "analyst statement"}
RECORD_ID = re.compile(r"(FIN|IOC|TIM|EVI|NOT|STA)-\d{4,}")
REPORT_ID = re.compile(r"(SA-\d{3,})(?:\.(\d+))?")  # SA-003 = its latest report, SA-003.2 = its second

# Common top-level domains. File extensions that are also country codes (.md .py .sh .pl .zip .mov .rs ...) are left
# out on purpose: a file name is far more likely than a domain in an analyst's report.
_TLDS = ("com|net|org|info|biz|io|co|me|tv|cc|ws|xyz|top|site|online|club|app|dev|cloud|live|shop|pro|icu|vip|buzz|"
         "link|click|ru|su|cn|ir|kp|ua|by|kz|tk|ml|ga|cf|gq|pw|us|uk|de|fr|nl|eu|jp|kr|in|br|ca|au|gov|mil|edu|int|"
         "arpa|onion|local|lan|corp|internal|home|ms|ly|to")
_IDENT = re.compile(
    r"(?<![\w.:/@-])(?:"
    r"(?P<case>(?:FIN|IOC|TIM|EVI|NOT|STA)-\d{4,}|SA-\d{3,}(?:\.\d+)?|EV-\d+|CVE-\d{4}-\d{4,7})"
    r"|(?P<attack>T\d{4}(?:\.\d{3})?)"
    r"|(?P<velo>C\.[0-9a-f]{16}|[FH]\.[0-9A-Z]{8,20})"
    r"|(?P<hash>[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})"
    r"|(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"|(?P<url>(?:https?|ftp)://[^\s<>\"'`)\]]+)"
    r"|(?P<email>[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"
    r"|(?P<mac>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"
    r"|(?P<v4>(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?::\d{1,5})?)"
    r"|(?P<v6>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?)"
    r"|(?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:" + _TLDS + r"))"
    r")(?![\w-]|\.\w)"
)


def _valid(m: re.Match[str]) -> bool:
    if v4 := m.group("v4"):
        try:
            ipaddress.IPv4Address(re.split(r"[/:]", v4)[0])
            return True
        except ValueError:
            return False
    if v6 := m.group("v6"):
        try:
            ipaddress.IPv6Address(v6.split("/")[0])
            return True
        except ValueError:  # a time (10:00:00), a MAC without its last pair, a ratio...
            return False
    return True


def identifiers(text: str, skip: str = "", limit: int = MAX_IDENTIFIERS) -> tuple[list[str], int]:
    """The exact identifiers in `text` (IPs, hashes, ids, times, URLs, domains, emails...), in order of first
    appearance, without those already in `skip`. Returns (identifiers, how many more were left out)."""
    seen: set[str] = set()
    out: list[str] = []
    times = more = 0
    for m in _IDENT.finditer(text):
        value = m.group(0).rstrip(".,;:")
        if value in seen or not _valid(m) or (skip and value in skip):
            continue
        seen.add(value)
        if m.group("time"):
            times += 1
            if times > MAX_TIMES:
                more += 1
                continue
        if len(out) >= limit:
            more += 1
            continue
        out.append(value[:160])
    return out, more


# ---- subagent reports ---------------------------------------------------------------------------------------------
_HEAD = re.compile(r"# Report from SA-\d{3,} \(report (SA-\d{3,}\.\d+)\) ")


def report_ref(content: str) -> str | None:
    """The id of the full report a lead's tool result holds (None: no report there, or it is shortened already). The
    header is the first line inside the wrapper: the harness writes it, before any text from the subagent."""
    first, _, rest = content.partition("\n")
    if not first.startswith("<tool_output "):
        return None
    head = rest.split("\n", 1)[0]
    m = _HEAD.match(head)
    return m.group(1) if m and not head.endswith(SHORT_MARK) else None


def _cut(text: str, limit: int) -> str:
    """The start of `text`, ended at a line or word break near `limit`."""
    if len(text) <= limit:
        return text
    cut = text.rfind("\n", 0, limit)
    if cut < limit // 2:
        cut = text.rfind(" ", 0, limit)
    return text[: cut if cut > limit // 2 else limit].rstrip()


def format_report(sa_id: str, title: str, expert: str, r: dict[str, Any], short: bool = False,
                  details_limit: int = 0, with_task: bool = False, footer: bool = True) -> str:
    """A report as an agent reads it. `short`: the shortened form the lead keeps once it has acted on the report.
    `details_limit`: the details are cut there, with a pointer to the rest (a report copied into a brief)."""
    ref = str(r.get("ref") or sa_id)
    out = [f"# Report from {sa_id} (report {ref}) - {title} ({expert})" + (f" {SHORT_MARK}" if short else ""),
           f"status: {r.get('status', '')} | confidence: {r.get('confidence') or 'unstated'}"]
    if with_task and r.get("task"):
        out.append(f"tasking: {r['task']}")
    if r.get("unstructured"):
        out.append("(the subagent answered in free text instead of submit_report)")
    summary, details = str(r.get("summary") or ""), str(r.get("details") or "")
    hidden = ""
    if short and len(summary) > SHORT_SUMMARY_CHARS:
        kept = _cut(summary, SHORT_SUMMARY_CHARS)
        hidden, summary = summary[len(kept):], kept + " [...]"
    out += ["## Bottom line", summary or "(empty)"]
    if r.get("key_facts"):
        out += ["## Key facts", *[f"- {f}" for f in r["key_facts"]]]
    tail = []
    if r.get("open_questions"):
        tail += ["## Open questions", *[f"- {q}" for q in r["open_questions"]]]
    if r.get("recommended_tasks"):
        tail += ["## Recommended tasks (your decision)",
                 *[f"- {t.get('expert') or 'any'}: {t.get('task', '')}" for t in r["recommended_tasks"]]]
    if short:
        hidden = (hidden + "\n" + details).strip()
        if hidden:
            out.append(f"## Details: {len(hidden):,} chars not repeated here; case_get([\"{ref}\"]) shows the full report")
            found, more = identifiers(hidden, skip="\n".join(out + tail))
            if found:
                out.append("Identifiers in them: " + ", ".join(found) + (f" (+{more} more)" if more else ""))
    elif details:
        if details_limit and len(details) > details_limit:
            kept = _cut(details, details_limit)
            details = f"{kept}\n[... {len(details) - len(kept):,} more chars: case_get([\"{ref}\"]) shows them]"
        out += ["## Details", details]
    out += tail
    if r.get("skills_used") and not short:
        out += ["## Skills used", *[f"- {u['name']}: {'worked' if u.get('worked') else 'DID NOT WORK'} {u.get('note', '')}"
                                    for u in r["skills_used"]]]
    if footer:
        out.append(f'(Follow up with subagent_message(subagent_id="{sa_id}", ...) - it keeps its context. '
                   f'Give this report to another subagent with refs=["{ref}"].)')
    return "\n".join(out)


# ---- case records -------------------------------------------------------------------------------------------------
def _value(v: Any) -> str:
    if isinstance(v, dict):
        return ", ".join(f"{k}={_value(x)}" for k, x in v.items())
    if isinstance(v, list):
        return ", ".join(_value(x) for x in v)
    return str(v)


def render_record(rec: dict[str, Any], limit: int = 0) -> str:
    """A case record as exact `field: value` pairs (empty fields left out; an evidence item's custody log is long and
    says nothing about the case, so only its last entry is kept)."""
    rid = str(rec.get("id", ""))
    fields = []
    for k, v in rec.items():
        if k == "id" or v in ("", None, [], {}):
            continue
        if k == "custody" and isinstance(v, list):
            v = v[-1]
            k = "last custody entry"
        fields.append(f"{k}: {_value(v)}")
    text = f"{rid} ({RECORD_KIND.get(rid[:3], 'record')}) " + "; ".join(fields)
    if limit and len(text) > limit:
        text = _cut(text, limit) + f" [... case_get([\"{rid}\"]) shows the rest]"
    return text


def parse_refs(refs: Any) -> list[str]:
    """Clean, de-duplicated, upper-case ids, in the order given."""
    out: list[str] = []
    items = refs if isinstance(refs, list) else re.split(r"[\s,;]+", refs) if isinstance(refs, str) else []
    for r in items:
        rid = str(r).strip().strip("[]\"'").upper()
        if rid and rid not in out:
            out.append(rid)
    return out
