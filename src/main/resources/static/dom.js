// dom.js -- shared DOM element references and small, presentation-agnostic
// utilities used by both the "Validar" and "Firmar" screens (T11b split
// app.js into modules: dom.js, render.js, validate.js, sign.js).
//
// Security note: every string that can come from the server or from an
// analyzed PDF (subject names, field names, anomaly/reason text, ...) is
// rendered with textContent, never innerHTML, everywhere in this project --
// see render.js. The only innerHTML use anywhere in these modules is the
// fixed, developer-authored SVG icon table below, never server data.

export const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024; // must match spring.servlet.multipart.max-file-size
const THEME_STORAGE_KEY = "pdfvalidator.theme";

// ---------------------------------------------------------------------
// Shared element references (header, tabs, results panel)
// ---------------------------------------------------------------------

export const themeToggle = document.getElementById("theme-toggle");
export const tabValidar = document.getElementById("tab-validar");
export const tabFirmar = document.getElementById("tab-firmar");
export const uploadPanel = document.getElementById("upload-panel");
export const firmarPanel = document.getElementById("firmar-panel");
export const resultsPanel = document.getElementById("results-panel");
export const verdictBanner = document.getElementById("verdict-banner");
export const sectionErrorsEl = document.getElementById("section-errors");
export const signaturesList = document.getElementById("signatures-list");
export const documentDetails = document.getElementById("document-details");
export const downloadJsonButton = document.getElementById("download-json");

// ---------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------

function readStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Private browsing / disabled storage: theme just won't persist.
  }
}

export function applyTheme(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.setAttribute("data-theme", theme);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

export function currentEffectiveTheme() {
  const explicit = document.documentElement.getAttribute("data-theme");
  if (explicit) return explicit;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function updateThemeToggleLabel() {
  const effective = currentEffectiveTheme();
  const nextLabel = effective === "dark" ? "Cambiar a tema claro" : "Cambiar a tema oscuro";
  themeToggle.setAttribute("aria-label", nextLabel);
  themeToggle.setAttribute("aria-pressed", String(effective === "dark"));
}

export function initTheme() {
  applyTheme(readStoredTheme());
  updateThemeToggleLabel();
}

themeToggle.addEventListener("click", () => {
  const next = currentEffectiveTheme() === "dark" ? "light" : "dark";
  applyTheme(next);
  storeTheme(next);
  updateThemeToggleLabel();
});

if (window.matchMedia) {
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (!readStoredTheme()) updateThemeToggleLabel();
  });
}

// ---------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

export function formatInstant(value) {
  if (!value) return "-";
  try {
    return new Intl.DateTimeFormat("es-ES", { dateStyle: "medium", timeStyle: "medium" }).format(new Date(value));
  } catch {
    return value;
  }
}

export function fact(label, value) {
  const wrap = document.createElement("div");
  const labelEl = document.createElement("div");
  labelEl.className = "fact-label";
  labelEl.textContent = label;
  const valueEl = document.createElement("div");
  valueEl.className = "fact-value";
  valueEl.textContent = value;
  wrap.append(labelEl, valueEl);
  return wrap;
}

export async function copyToClipboard(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    button.dataset.copied = "true";
    setTimeout(() => delete button.dataset.copied, 1500);
  } catch {
    // Clipboard API unavailable (permissions, insecure context): fail silently.
  }
}

// ---------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------

const ICONS = {
  check: '<path d="M20 6 9 17l-5-5"/>',
  warning: '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="m10.29 3.86-8.48 14.7A1 1 0 0 0 2.66 20h18.68a1 1 0 0 0 .85-1.44L13.71 3.86a1 1 0 0 0-1.72 0Z"/>',
  cross: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
};

export function svgIcon(name, extraClass) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "20");
  svg.setAttribute("height", "20");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  if (extraClass) svg.setAttribute("class", extraClass);
  // ICONS values are a fixed, developer-authored lookup table (not server
  // data), so this is the one safe, deliberate use of innerHTML in this file.
  svg.innerHTML = ICONS[name] || ICONS.info;
  return svg;
}

// ---------------------------------------------------------------------
// PDF file helpers (shared by the Validar and Firmar upload zones)
// ---------------------------------------------------------------------

export function looksLikePdfFile(file) {
  const nameIsPdf = /\.pdf$/i.test(file.name || "");
  const typeIsPdf = file.type === "application/pdf" || file.type === "";
  return nameIsPdf && typeIsPdf;
}

const PDF_MAGIC_BYTES = [0x25, 0x50, 0x44, 0x46, 0x2d]; // "%PDF-"

/**
 * Reads only the first 5 bytes of the file to check the PDF magic number,
 * independently of the name/extension check above. Used by the Firmar
 * screen (T11b) before handing a file to AutoFirma: a mislabeled or
 * malicious non-PDF file must never reach the signing flow.
 */
export async function hasPdfMagicBytes(file) {
  try {
    const header = new Uint8Array(await file.slice(0, PDF_MAGIC_BYTES.length).arrayBuffer());
    return PDF_MAGIC_BYTES.every((byte, index) => header[index] === byte);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------
// Base64 / Blob helpers (Firmar screen: reading a PDF to send to AutoFirma,
// and turning its base64 response back into a downloadable file)
// ---------------------------------------------------------------------

export function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      const commaIndex = result.indexOf(",");
      resolve(commaIndex === -1 ? result : result.slice(commaIndex + 1));
    };
    reader.onerror = () => reject(reader.error || new Error("No se pudo leer el archivo."));
    reader.readAsDataURL(file);
  });
}

/** AutoScript returns URL-safe base64 without padding; this accepts both. */
export function base64ToBlob(base64, mimeType) {
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Blob([bytes], { type: mimeType });
}

export function downloadBlob(blob, fileName) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
