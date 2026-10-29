/* ZenLens service worker: context menu, toolbar badge. No network access, no storage of values. */

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
    } catch (e) { console.warn("ZenLens: cannot redact on this page", e && e.message); }
  }
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.type === "zl:count" && sender.tab && sender.tab.id != null) {
    const n = msg.total | 0;
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: n ? String(n > 999 ? "999+" : n) : "" });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#7048e8" });
  }
});

// Side panel opens from the popup's "Privacy preview" button; clicking the toolbar icon shows the popup.
chrome.sidePanel && chrome.sidePanel.setPanelBehavior && chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
