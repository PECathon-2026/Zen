"""Agent loop: sanitized view -> egress_check -> llm.next_action -> executor validate/approve -> execute -> repeat.

Logs carry only ids, kinds, origins and placeholder names.
"""
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .executor import Executor, Page, Rejected, _safe, describe
from .gate import Blocked, egress_check
from .llm import LLM, Action, build_payload
from .sanitize import redact

log = logging.getLogger("zenlens.agent")


@dataclass
class Result:
    status: str  # done | ask_user | max_steps | blocked | error
    steps: int
    history: list[dict] = field(default_factory=list)
    reason: str = ""

    @property
    def rejections(self) -> list[str]:
        return [h["result"] for h in self.history if h["result"] != "ok"]


def safe_url(url: str) -> str:
    """Drop query and fragment (tokens, emails, ids live there) before the URL leaves the machine."""
    p = urlsplit(url or "")
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def _scrub(a: Action) -> dict:
    """History is sent back to the model: redact anything the model emitted that the detector flags."""
    d = {k: redact(v)[0] if k in ("text", "url", "reason") else v for k, v in a.to_dict().items()}
    d.update({k: _safe(d[k]) for k in ("type", "target") if k in d})
    return d


def capture_view(page: Page) -> dict:
    return {"url": safe_url(page.url()), "elements": page.elements()}


def run(goal: str, page: Page, llm: LLM, executor: Executor, max_steps: int = 10,
        canaries: tuple[str, ...] = ()) -> Result:
    canaries = tuple(canaries) + executor.vault.canaries()
    ps = getattr(executor, "pseudonymizer", None)
    history: list[dict] = []
    for step in range(1, max_steps + 1):
        try:
            view = capture_view(page)  # a live page's sanitized_view may itself raise Blocked
            # pseudonym values are learnt as pages are seen: re-read them every step
            egress_check(build_payload(goal, view, history), canaries + (ps.canaries() if ps is not None else ()))
        except Blocked as e:  # fail closed: nothing goes to the model
            log.warning("step %d: egress %s", step, e)
            return Result("blocked", step, history, str(e))
        try:
            action = llm.next_action(goal, view, history)
        except Blocked as e:
            log.warning("step %d: egress %s", step, e)
            return Result("blocked", step, history, str(e))
        except Exception as e:
            log.error("step %d: llm error %s", step, type(e).__name__)
            return Result("error", step, history, f"llm error: {type(e).__name__}")
        log.info("step %d: %s", step, describe(action))
        if action.type in ("done", "ask_user"):
            return Result(action.type, step, history, "")
        try:
            result = executor.run(action, view)
        except Rejected as e:
            result = f"rejected: {e}"
            log.warning("step %d: %s", step, result)
        history.append({"action": _scrub(action), "result": result})
    return Result("max_steps", max_steps, history, "")
