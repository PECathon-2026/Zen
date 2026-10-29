"""High-level entry points for the app/demo: run_task (agent loop on a live headless page) and preview (one capture).

Every returned dict is JSON-safe and holds only sanitized data: ids, kinds, counts, placeholder names, [REDACTED:*].
The final report is egress-checked against the vault canaries; on any hit the report itself is withheld (fail closed).
"""
import base64
import json
import logging
from typing import Callable

from . import agent
from .browser import PlaywrightPage, redaction_counts
from .capture import Session, _clean_url, capture, sanitized_view
from .executor import Executor, Rejected, _safe, describe, origin
from .gate import Blocked, egress_check
from .llm import LLM, Action, ClaudeLLM, ScriptedLLM
from .sanitize import redact
from .vault import Vault

log = logging.getLogger("zenlens.runner")


def _privacy(view: dict) -> dict:
    c = redaction_counts(view)
    return {"redactions": c, "total": sum(c.values()),
            "sensitive_fields": sum(1 for e in view.get("elements", []) if e.get("sensitive"))}


class _Tap:
    """Wraps the LLM: records the view's privacy counts and the proposed action per step."""

    def __init__(self, llm: LLM, steps: list[dict]):
        self.llm, self.steps = llm, steps

    def next_action(self, goal, view, history):
        a = self.llm.next_action(goal, view, history)
        self.steps.append({"step": len(self.steps) + 1, "action": describe(a), "type": _safe(a.type),
                           "target": _safe(a.target) if a.target else None, "reason": redact(a.reason)[0][:200],
                           "verdict": a.type if a.type in ("done", "ask_user") else None, "result": None,
                           "needs_approval": False, "approval_reason": None, "approved": None,
                           "privacy": _privacy(view)})
        return a


class _Exec(Executor):
    """Executor that fills in the current step's verdict and approval outcome."""

    def __init__(self, *a, steps: list[dict], on_step=None, **kw):
        super().__init__(*a, **kw)
        self.steps, self.on_step = steps, on_step

    def _approved(self, a, reason):
        ok = super()._approved(a, reason)
        self.steps[-1].update(needs_approval=True, approval_reason=reason, approved=ok)
        return ok

    def run(self, a, view):
        s = self.steps[-1]
        try:
            r = super().run(a, view)
            s.update(verdict="ok", result=r)
            return r
        except Rejected as e:
            s.update(verdict="rejected", result=f"rejected: {e}")
            raise
        finally:
            if self.on_step:
                self.on_step(dict(s))


def _make_llm(llm, script, canaries) -> tuple[LLM, str]:
    if llm == "scripted":
        return ScriptedLLM(script or []), "scripted"
    if llm == "claude":
        return ClaudeLLM(canaries=canaries), "claude"
    if isinstance(llm, str):
        raise ValueError("llm must be 'scripted', 'claude' or an LLM object")
    return llm, type(llm).__name__


def _approver(approve):
    if approve is True:  # explicit opt-in: approve everything (demo only)
        return lambda a, r: True
    return approve or None  # None -> executor denies


def run_task(goal: str, start_url: str, *, llm="scripted", script: list[dict] | None = None, allowed_origins=None,
             vault=None, approve: Callable[[Action, str], bool] | bool | None = None, max_steps: int = 10,
             headless: bool = True, on_step: Callable[[dict], None] | None = None) -> dict:
    """Run the agent on a live headless page. Returns a JSON-safe, sanitized report (see module docstring)."""
    vault = vault if isinstance(vault, Vault) else Vault(vault or {})
    canaries = vault.canaries()
    allowed = list(allowed_origins) if allowed_origins is not None else [o for o in [origin(start_url)] if o]
    model, llm_name = _make_llm(llm, script, canaries)
    steps: list[dict] = []
    report = {"status": "error", "reason": "", "goal": redact(goal)[0], "start_url": _clean_url(start_url),
              "final_url": None, "allowed_origins": sorted({origin(o) or o for o in allowed}), "llm": llm_name,
              "steps": steps, "rejected": 0, "final_view": None, "final_privacy": None}
    try:
        with Session(headless=headless) as s:
            page = PlaywrightPage(s, allowed, canaries)
            page.goto(start_url)
            ex = _Exec(page, allowed, vault, _approver(approve), steps=steps, on_step=on_step)
            res = agent.run(goal, page, _Tap(model, steps), ex, max_steps=max_steps)
            report.update(status=res.status, reason=res.reason, final_url=_clean_url(page.url()))
            try:
                report["final_view"] = page.view()
                report["final_privacy"] = _privacy(report["final_view"])
            except Blocked as e:
                report["reason"] = report["reason"] or f"final view withheld: {e}"
    except Exception as e:  # never str(e): browser errors can echo URLs/values
        log.error("run_task failed: %s", type(e).__name__)
        report.update(status="error", reason=f"{type(e).__name__}")
    if steps and steps[-1]["verdict"] in ("done", "ask_user") and on_step:
        on_step(dict(steps[-1]))
    report["rejected"] = sum(1 for st in steps if st["verdict"] == "rejected")
    try:
        egress_check(json.dumps(report, ensure_ascii=False), canaries)
    except Blocked as e:  # fail closed: something unsafe slipped into the report
        return {"status": "error", "reason": f"report withheld: {e}", "steps": [], "llm": llm_name}
    return report


def _box(bbox) -> tuple[int, int, int, int]:
    x, y, w, h = bbox
    return x, y, x + w, y + h


def preview(target: str, *, faces: bool = True) -> dict:
    """Capture once and return {url, title, view, redactions, sensitive_elements, screenshot (b64 redacted PNG | None),
    screenshot_redactions, screenshot_reason}. Never returns the raw screenshot."""
    snap = capture(target)
    out = {"url": _clean_url(snap.url), "title": None, "view": None, "redactions": {}, "sensitive_elements": [],
           "screenshot": None, "screenshot_redactions": {}, "screenshot_reason": None}
    try:
        view = sanitized_view(snap)
    except Blocked as e:
        out["screenshot_reason"] = f"view withheld: {e}"
        return out
    flagged = [e for e in view["elements"]
               if e.get("sensitive") or "[REDACTED:" in f'{e.get("text") or ""}{e.get("value") or ""}']
    out.update(title=view["title"], view=view, redactions=redaction_counts(view),
               sensitive_elements=[{"id": e["id"], "kind": e.get("sensitive") or "TEXT", "bbox": e["bbox"]}
                                   for e in flagged])
    try:
        from .screenshot import RedactionError, redact_image
    except ImportError as e:
        out["screenshot_reason"] = f"screenshot redaction unavailable: {type(e).__name__}"
        return out
    try:
        png, reds = redact_image(snap.screenshot, extra_boxes=[_box(e["bbox"]) for e in flagged if e.get("bbox")],
                                 faces=faces)
    except RedactionError as e:
        out["screenshot_reason"] = str(e)
        return out
    c: dict[str, int] = {}
    for r in reds:
        c[r.kind] = c.get(r.kind, 0) + 1
    out.update(screenshot=base64.b64encode(png).decode("ascii"), screenshot_redactions=dict(sorted(c.items())))
    return out
