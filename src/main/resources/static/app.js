// Validador PDF -- frontend entry point (vanilla ES module, no build step,
// no CDNs). T11b split what used to be one file into small ES modules:
// dom.js (shared element refs + utilities), render.js (report rendering),
// validate.js (the "Validar" screen) and sign.js (the "Firmar" screen).
// This file only wires the two together: theme toggle (dom.js) and tab
// navigation between them.

import { initTheme, tabValidar, tabFirmar, switchTab } from "./dom.js";
import "./validate.js";
import { ensureAutoScriptReady } from "./sign.js";

function activateTab(tab) {
  switchTab(tab);
  if (tab === "firmar") {
    // Lazy AutoScript initialization: only once the user actually opens the
    // Firmar tab, never on the (much more common) plain Validar visit.
    ensureAutoScriptReady();
  }
}

tabValidar.addEventListener("click", () => activateTab("validar"));
tabFirmar.addEventListener("click", () => activateTab("firmar"));

initTheme();
