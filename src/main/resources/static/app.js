// Validador PDF -- frontend entry point (vanilla ES module, no build step,
// no CDNs). T11b split what used to be one file into small ES modules:
// dom.js (shared element refs + utilities), render.js (report rendering),
// validate.js (the "Validar" screen) and sign.js (the "Firmar" screen).
// This file only wires the two together: theme toggle (dom.js) and tab
// navigation between them.

import { initTheme, tabValidar, tabFirmar, uploadPanel, firmarPanel, resultsPanel } from "./dom.js";
import "./validate.js";
import { ensureAutoScriptReady } from "./sign.js";

function activateTab(tab) {
  const isValidar = tab === "validar";
  uploadPanel.hidden = !isValidar;
  firmarPanel.hidden = isValidar;
  resultsPanel.hidden = true;

  tabValidar.classList.toggle("is-active", isValidar);
  tabFirmar.classList.toggle("is-active", !isValidar);
  if (isValidar) {
    tabValidar.setAttribute("aria-current", "page");
    tabFirmar.removeAttribute("aria-current");
  } else {
    tabFirmar.setAttribute("aria-current", "page");
    tabValidar.removeAttribute("aria-current");
    // Lazy AutoScript initialization: only once the user actually opens the
    // Firmar tab, never on the (much more common) plain Validar visit.
    ensureAutoScriptReady();
  }
}

tabValidar.addEventListener("click", () => activateTab("validar"));
tabFirmar.addEventListener("click", () => activateTab("firmar"));

initTheme();
