/* Zen service worker: context menu, toolbar badge. No network access, no storage of values. */

const MENU_ID = "zenlens-redact-copy";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: MENU_ID, title: "Redact selection & copy", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID || !tab || tab.id == null) return;
  const msg = { type: "zl:redactSelection", fallback: info.selectionText || "" };
  try {
    await chrome.tabs.sendMessage(tab.id, msg);
  } catch (_) {
    // No content script (e.g. page loaded before install): inject via activeTab grant from the menu click.
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id },
        files: ["lib/detect.js", "lib/structural.js", "lib/settings.js", "content/content.js", "content/guard.js"] });
      await chrome.tabs.sendMessage(tab.id, msg);
    } catch (e) { console.warn("Zen: cannot redact on this page", e && e.message); }
  }
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg && msg.type === "zl:count" && sender.tab && sender.tab.id != null) {
    const n = msg.total | 0;
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: msg.shield && !n ? "ON" : n ? String(n > 999 ? "999+" : n) : "" });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: msg.shield ? "#b8431e" : "#7048e8" });
  }
  // Agent detection: is any debugger client (another extension's agent, DevTools, a CDP script) attached to this tab?
  // We never attach ourselves, so this shows no infobar. Only a boolean leaves this function.
  if (msg && msg.type === "zl:probe" && sender.tab && sender.tab.id != null) {
    chrome.debugger.getTargets()
      .then((ts) => reply({ agent: ts.some((t) => t.tabId === sender.tab.id && t.attached) }))
      .catch(() => reply({ agent: false }));
    return true;
  }
});

// Side panel opens from the popup's "Privacy preview" button; clicking the toolbar icon shows the popup.
chrome.sidePanel && chrome.sidePanel.setPanelBehavior && chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
