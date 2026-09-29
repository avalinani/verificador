// validate.js -- the "Validar" screen: upload a PDF (drag & drop or file
// picker), POST it to the analysis API, and render the report (render.js).
//
// `analyzeFile` is also called directly by the Firmar screen's "Validar
// este PDF" button (sign.js), so the signed PDF is analyzed through the
// exact same code path -- no duplicated upload/render logic.

import { MAX_FILE_SIZE_BYTES, looksLikePdfFile, formatBytes, downloadJsonButton } from "./dom.js";
import { renderReport, hideResults } from "./render.js";

const ANALYZE_URL = "/api/v1/pdf/analyze";

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const fileChip = document.getElementById("file-chip");
const fileChipName = document.getElementById("file-chip-name");
const fileChipSize = document.getElementById("file-chip-size");
const fileChipRemove = document.getElementById("file-chip-remove");
const checkRevocation = document.getElementById("check-revocation");
const analyzeButton = document.getElementById("analyze-button");
const analyzeSpinner = document.getElementById("analyze-spinner");
const analyzeForm = document.getElementById("analyze-form");
const statusLine = document.getElementById("status-line");
const errorBanner = document.getElementById("error-banner");

let selectedFile = null;
let lastReport = null;

// ---------------------------------------------------------------------
// File selection
// ---------------------------------------------------------------------

function setSelectedFile(file) {
  clearError();
  if (!file) {
    clearSelectedFile();
    return;
  }
  if (!looksLikePdfFile(file)) {
    // A previously selected (valid) file must not silently stay selected
    // behind the scenes while the UI shows the rejected file's name.
    clearSelectedFile();
    showError("El archivo seleccionado no parece un PDF. Elige un archivo con extensión .pdf.");
    return;
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
    clearSelectedFile();
    showError(`El archivo supera el tamaño máximo permitido (20 MB). Tamaño actual: ${formatBytes(file.size)}.`);
    return;
  }
  selectedFile = file;
  fileChipName.textContent = file.name;
  fileChipSize.textContent = formatBytes(file.size);
  fileChip.hidden = false;
  analyzeButton.disabled = false;
  statusLine.textContent = "";
}

function clearSelectedFile() {
  selectedFile = null;
  fileInput.value = "";
  fileChipName.textContent = "";
  fileChipSize.textContent = "";
  fileChip.hidden = true;
  analyzeButton.disabled = true;
}

dropzone.addEventListener("click", () => {
  if (isAnalyzing()) return;
  fileInput.click();
});
dropzone.addEventListener("keydown", (event) => {
  if (isAnalyzing()) return;
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});

["dragenter", "dragover"].forEach((eventName) => {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("is-dragover");
  });
});

["dragleave", "dragend"].forEach((eventName) => {
  dropzone.addEventListener(eventName, () => dropzone.classList.remove("is-dragover"));
});

dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropzone.classList.remove("is-dragover");
  if (isAnalyzing()) return;
  const file = event.dataTransfer?.files?.[0];
  if (file) setSelectedFile(file);
});

fileInput.addEventListener("change", () => {
  setSelectedFile(fileInput.files?.[0] ?? null);
});

fileChipRemove.addEventListener("click", () => {
  clearError();
  clearSelectedFile();
});

// ---------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------

// The AbortController for the in-flight analyze() request, or null when
// none is running -- both the single source of truth for isAnalyzing() and
// the means to cancel a stale request if a new one is ever allowed to
// start. Shared across the Validar form and the Firmar "Validar este PDF"
// button (sign.js), since both funnel through analyzeFile(): only one
// analysis -- from either screen -- can be in flight at a time.
let inFlightAnalysis = null;

export function isAnalyzing() {
  return inFlightAnalysis !== null;
}

analyzeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  // Concurrent-submit guard: a second submit (double click, Enter held
  // down, a synthetic event) while a request is already in flight is
  // ignored outright rather than starting an overlapping request.
  if (!selectedFile || isAnalyzing()) return;
  void analyzeFile(selectedFile, checkRevocation.checked);
});

/**
 * Uploads `file` to the analysis API and renders the result. Exported so
 * the Firmar screen's "Validar este PDF" button (sign.js) can reuse this
 * exact flow for the signed PDF it just received from AutoFirma, instead
 * of duplicating the fetch/render logic.
 */
export async function analyzeFile(file, wantsRevocationCheck) {
  const controller = new AbortController();
  inFlightAnalysis = controller;
  setLoading(true);
  clearError();
  hideResults();

  const formData = new FormData();
  formData.append("file", file, file.name);

  const url = `${ANALYZE_URL}?checkRevocation=${wantsRevocationCheck ? "true" : "false"}`;

  let response;
  try {
    response = await fetch(url, { method: "POST", body: formData, signal: controller.signal });
  } catch (error) {
    inFlightAnalysis = null;
    setLoading(false);
    if (error?.name === "AbortError") return;
    showError("No se pudo conectar con el servidor. Comprueba tu conexión e inténtalo de nuevo.");
    return;
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  inFlightAnalysis = null;
  setLoading(false);

  if (!response.ok) {
    showError(describeError(response.status, payload));
    return;
  }

  if (!isValidReportPayload(payload)) {
    showError("El servidor devolvió una respuesta inesperada. Inténtalo de nuevo más tarde.");
    return;
  }

  lastReport = payload;
  renderReport(payload);
}

/**
 * Minimal structural check on a successful (2xx) response body before
 * handing it to the renderers, which assume the report's shape and would
 * otherwise throw on a missing/malformed field (e.g. a proxy returning an
 * unexpected 200, or a truncated response `fetch` still resolved as "ok").
 */
function isValidReportPayload(payload) {
  return Boolean(
    payload &&
      typeof payload === "object" &&
      typeof payload.overallVerdict === "string" &&
      Array.isArray(payload.signatures) &&
      payload.hashes &&
      typeof payload.hashes === "object" &&
      payload.structure &&
      typeof payload.structure === "object" &&
      payload.security &&
      typeof payload.security === "object" &&
      payload.pdfa &&
      typeof payload.pdfa === "object",
  );
}

function setLoading(isLoading) {
  analyzeButton.disabled = isLoading || !selectedFile;
  analyzeSpinner.hidden = !isLoading;
  statusLine.textContent = isLoading ? "Analizando el documento..." : "";
  dropzone.setAttribute("aria-disabled", String(isLoading));
}

function describeError(status, problem) {
  const type = problem?.type ?? "";
  if (type.endsWith("missing-file")) return "Falta el archivo o está vacío. Selecciona un PDF antes de continuar.";
  if (type.endsWith("not-a-pdf")) return "El contenido subido no es un PDF válido.";
  if (type.endsWith("corrupt-pdf")) return "El PDF está dañado y no se pudo analizar.";
  if (type.endsWith("encrypted-pdf")) return "El PDF está cifrado con contraseña y no se puede analizar.";
  if (type.endsWith("file-too-large") || status === 413) return "El archivo supera el tamaño máximo permitido (20 MB).";
  if (type === "urn:pdfvalidator:error:busy") {
    return "El servicio está ocupado analizando otros documentos. Inténtalo de nuevo en unos segundos.";
  }
  if (status === 503) return "El servicio no está disponible en este momento. Inténtalo de nuevo más tarde.";
  if (status === 500) return "Se produjo un error inesperado en el servidor. Inténtalo de nuevo más tarde.";
  return problem?.detail || "No se pudo completar el análisis. Inténtalo de nuevo.";
}

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.hidden = false;
}

function clearError() {
  errorBanner.hidden = true;
  errorBanner.textContent = "";
}

// ---------------------------------------------------------------------
// Download JSON
// ---------------------------------------------------------------------

downloadJsonButton.addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `informe-${(lastReport.fileName || "documento").replace(/[^a-zA-Z0-9._-]/g, "_")}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
});
