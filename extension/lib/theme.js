/* Apply the saved Zen theme (system / light / dark) to an extension page before it paints. */
(function () {
  const root = document.documentElement;
  const apply = (t) => { const eff = t === "light" || t === "dark" ? t : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; root.dataset.theme = eff; return eff; };
  apply("system");
  try { chrome.storage.sync.get({ theme: "system" }).then((g) => apply(g.theme)); } catch (_) { /* keep system */ }
  globalThis.ZenTheme = { apply };
})();
