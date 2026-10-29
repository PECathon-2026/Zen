"""Real-browser `Page` for the executor/agent: every element list handed out is the sanitized view.

Raw values stay in the local snapshot; click/fill resolve ids to locators locally.
"""
from .capture import Session, sanitized_view, snapshot_page


class PlaywrightPage:
    def __init__(self, session: Session, canaries: tuple[str, ...] = ()):
        self.session, self.canaries, self._snap = session, tuple(canaries), None

    def url(self) -> str:
        return self.session.page.url

    def elements(self) -> list[dict]:
        self._snap = snapshot_page(self.session.page)
        # bbox is layout noise for the model and its digits can collide with short secrets
        return [{k: v for k, v in e.items() if k != "bbox"} for e in sanitized_view(self._snap, self.canaries)["elements"]]

    def _locator(self, id: str):
        if self._snap is None:
            raise RuntimeError("call elements() before acting")
        return self._snap.locator_for(id)

    def click(self, id: str) -> None:
        self._locator(id).click(timeout=5000)

    def fill(self, id: str, text: str) -> None:
        self._locator(id).fill(text, timeout=5000)

    def navigate(self, url: str) -> None:
        self.session.page.goto(url, wait_until="load")
