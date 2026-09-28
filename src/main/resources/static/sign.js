// sign.js -- the "Firmar" screen (T11b): sign a PDF locally with the user's
// own certificate through AutoFirma (the official desktop signing
// application), using the vendored AutoScript library
// (vendor/autofirma/autoscript.js, unmodified -- see NOTICE.md).
//
// How this stays desktop-only with no intermediate storage/retrieve
// server: `AutoScript.cargarAppAfirma()` is called WITHOUT
// `setForceWSMode(true)`. That flag is misleadingly named -- verified
// directly in the AutoScript 1.10.1 source, not assumed from its name --
// it forces the *intermediate web-service* transport (`AppAfirmaJSWebService`,
// which needs server-side storage/retriever servlets we deliberately never
// configure), not WebSocket mode. Left unset, a modern desktop browser with
// WebSocket support (every browser this project targets) automatically
// picks `AppAfirmaWebSocketClient`, which talks directly to AutoFirma on
// `wss://127.0.0.1:<port>` -- no server in the middle at all. The private
// key never leaves the user's machine: this module only ever sends the
// unsigned PDF's bytes to AutoFirma (over that local WebSocket) and
// receives the signed PDF's bytes back; the actual private-key operation
// happens entirely inside AutoFirma.
//
// AutoScript's own support dialog is explicitly disabled
// (`SupportDialog.enableSupportDialog(false)`) rather than left on: it
// otherwise injects its own inline-styled loading/error modal (an
// unnecessary duplicate of the waiting/error UI below), which is also the
// one place in this vendored library that would need a looser `style-src`
// to render correctly -- turning it off avoids that entirely instead of
// loosening the CSP.

import {
  looksLikePdfFile,
  hasPdfMagicBytes,
  formatBytes,
  fileToBase64,
  base64ToBlob,
  downloadBlob,
  switchTab,
  resultsHeading,
  resultsPanel,
  MAX_FILE_SIZE_BYTES,
} from "./dom.js";
import { analyzeFile, isAnalyzing } from "./validate.js";

const SIGN_ALGORITHM = "SHA256withRSA";
const SIGN_FORMAT = "PAdES";
const AUTOFIRMA_DOWNLOAD_URL = "https://firmaelectronica.gob.es/Home/Descargas.html";

const dropzone = document.getElementById("firmar-dropzone");
const fileInput = document.getElementById("firmar-file-input");
const fileChip = document.getElementById("firmar-file-chip");
const fileChipName = document.getElementById("firmar-file-chip-name");
const fileChipSize = document.getElementById("firmar-file-chip-size");
const fileChipRemove = document.getElementById("firmar-file-chip-remove");
const reasonInput = document.getElementById("firmar-reason");
const firmarButton = document.getElementById("firmar-button");
const firmarSpinner = document.getElementById("firmar-spinner");
const firmarForm = document.getElementById("firmar-form");
const waitingPanel = document.getElementById("firmar-waiting");
const waitingText = document.getElementById("firmar-waiting-text");
const cancelButton = document.getElementById("firmar-cancel-button");
const statusLine = document.getElementById("firmar-status-line");
const errorBanner = document.getElementById("firmar-error-banner");
const resultPanel = document.getElementById("firmar-result");
const resultMessage = document.getElementById("firmar-result-message");
const downloadButton = document.getElementById("firmar-download-button");
const validateButton = document.getElementById("firmar-validate-button");

let selectedFile = null;
let signedBlob = null;
let signedFileName = null;

// `null` when idle, otherwise the generation number of the in-flight sign
// operation -- see cancel() below for why this exists instead of trying to
// actually abort AutoFirma (there is no such API).
let inFlightGeneration = null;
let nextGeneration = 1;
let autoScriptInitialized = false;

function isSigning() {
  return inFlightGeneration !== null;
}

function isBusy() {
  return isSigning() || isAnalyzing();
}

/**
 * Lazily initializes AutoScript the first time the Firmar tab is opened
 * (called from app.js) -- cheap and side-effect-free until `sign()` is
 * actually invoked, so it never delays or affects the Validar screen.
 */
export function ensureAutoScriptReady() {
  if (autoScriptInitialized) return;
  autoScriptInitialized = true;
  if (window.SupportDialog) {
    window.SupportDialog.enableSupportDialog(false);
  }
  if (window.AutoScript) {
    window.AutoScript.cargarAppAfirma();
  }
}

// ---------------------------------------------------------------------
// File selection
// ---------------------------------------------------------------------

async function setSelectedFile(file) {
  clearError();
  hideResult();
  if (!file) {
    clearSelectedFile();
    return;
  }
  if (!looksLikePdfFile(file)) {
    clearSelectedFile();
    showError("El archivo seleccionado no parece un PDF. Elige un archivo con extensión .pdf.");
    return;
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
    clearSelectedFile();
    showError(`El archivo supera el tamaño máximo permitido (20 MB). Tamaño actual: ${formatBytes(file.size)}.`);
    return;
  }
  if (!(await hasPdfMagicBytes(file))) {
    clearSelectedFile();
    showError("El contenido del archivo no es un PDF válido (no empieza por la cabecera %PDF-).");
    return;
  }
  selectedFile = file;
  fileChipName.textContent = file.name;
  fileChipSize.textContent = formatBytes(file.size);
  fileChip.hidden = false;
  firmarButton.disabled = false;
  statusLine.textContent = "";
}

function clearSelectedFile() {
  selectedFile = null;
  fileInput.value = "";
  fileChipName.textContent = "";
  fileChipSize.textContent = "";
  fileChip.hidden = true;
  firmarButton.disabled = true;
}

dropzone.addEventListener("click", () => {
  if (isBusy()) return;
  fileInput.click();
});
dropzone.addEventListener("keydown", (event) => {
  if (isBusy()) return;
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
  if (isBusy()) return;
  const file = event.dataTransfer?.files?.[0];
  if (file) void setSelectedFile(file);
});

fileInput.addEventListener("change", () => {
  void setSelectedFile(fileInput.files?.[0] ?? null);
});

fileChipRemove.addEventListener("click", () => {
  clearError();
  clearSelectedFile();
});

// ---------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------

firmarForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selectedFile || isBusy()) return;
  void startSigning(selectedFile);
});

cancelButton.addEventListener("click", () => {
  // There is no AutoScript API to abort an in-flight native operation --
  // AutoFirma may still be running on the user's machine. "Cancel" here
  // means this page stops waiting for it: bumping the generation makes the
  // eventual success/error callback (if AutoFirma ever answers) a no-op.
  inFlightGeneration = null;
  setWaiting(false);
  showError("Has cancelado la operación de firma.");
});

async function startSigning(file) {
  clearError();
  hideResult();
  ensureAutoScriptReady();

  if (!window.AutoScript) {
    showError(
      `No se pudo cargar el componente de firma. Comprueba tu conexión y recarga la página. ` +
        `Si el problema persiste, instala AutoFirma desde ${AUTOFIRMA_DOWNLOAD_URL}.`,
    );
    return;
  }

  const generation = nextGeneration;
  nextGeneration += 1;
  inFlightGeneration = generation;
  setWaiting(true);

  let dataB64;
  try {
    dataB64 = await fileToBase64(file);
  } catch {
    inFlightGeneration = null;
    setWaiting(false);
    showError("No se pudo leer el archivo seleccionado. Inténtalo de nuevo.");
    return;
  }

  // Still the current operation? (not cancelled while reading the file)
  if (inFlightGeneration !== generation) return;

  const extraParams = buildExtraParams(reasonInput.value);

  window.AutoScript.sign(
    dataB64,
    SIGN_ALGORITHM,
    SIGN_FORMAT,
    extraParams,
    (signatureB64) => onSignSuccess(generation, file, signatureB64),
    (exceptionType, errorMessage, errorCode) => onSignError(generation, exceptionType, errorMessage, errorCode),
  );
}

function onSignSuccess(generation, originalFile, signatureB64) {
  if (inFlightGeneration !== generation) return; // cancelled or superseded
  inFlightGeneration = null;
  setWaiting(false);

  // Guard against a malformed/empty payload (unexpected AutoScript response,
  // truncated WebSocket message, ...): base64ToBlob's atob()/replace() calls
  // throw on invalid input, which must never surface as an uncaught
  // exception -- it becomes a normal Spanish error state instead.
  try {
    signedBlob = base64ToBlob(signatureB64, "application/pdf");
  } catch {
    signedBlob = null;
    showError("AutoFirma devolvió una respuesta que no se pudo interpretar. Inténtalo de nuevo.");
    return;
  }
  signedFileName = signedFileNameFor(originalFile.name);
  resultMessage.textContent = "El documento se ha firmado correctamente con tu certificado.";
  resultPanel.hidden = false;
}

function onSignError(generation, exceptionType, errorMessage, errorCode) {
  if (inFlightGeneration !== generation) return; // already cancelled locally
  inFlightGeneration = null;
  setWaiting(false);
  showError(describeSignError(exceptionType, errorMessage, errorCode));
}

function signedFileNameFor(originalName) {
  const base = originalName.replace(/\.pdf$/i, "");
  return `${base}-firmado.pdf`;
}

/**
 * Turns the "Motivo de la firma" field into the `properties`-style string
 * AutoScript expects as `extraParams` (a Java Properties document, one
 * `key=value` pair per line -- verified against the AutoScript source,
 * `configureExtraParams`, which base64-encodes this string as-is before
 * sending it on). `signReason` is PAdES's standard reason property
 * (`es.gob.afirma.signers.pades.common.PdfExtraParams.SIGN_REASON`,
 * confirmed in the same official repository). No other extraParams key is
 * set, so the signature stays invisible (the default).
 *
 * Non-ASCII "motivo" (T11e): a plain JS string with tildes/ñ/em dash etc. is
 * passed through as-is here, deliberately -- verified directly in the
 * vendored `autoscript.js` (`Base64.encode`, `~line 5728`) that it always
 * runs its input through `_utf8_encode` (`~line 5862`, a standard UTF-8
 * byte-encoder) before base64-encoding it, for every `extraParams` call site
 * in the file (`configureExtraParams`, `~line 5373`, is the one `sign()`
 * uses). There is no separate escaping/encoding convention for Unicode in
 * this library's public API, so re-encoding the string ourselves before
 * handing it to `AutoScript.sign` would double-encode it and corrupt
 * accented characters instead of preserving them.
 */
function buildExtraParams(reason) {
  const trimmed = (reason || "").trim();
  if (!trimmed) return null;
  const escaped = trimmed.replace(/[\\=:#!]/g, (match) => `\\${match}`).replace(/[\r\n]+/g, " ");
  return `signReason=${escaped}\n`;
}

// ---------------------------------------------------------------------
// Error mapping (AutoScript error codes -> Spanish text)
//
// Codes verified directly in the AutoScript 1.10.1 source (`ErrorCode`
// object and the WebSocket client's retry/failure paths), not guessed:
// - AS500001 (`CANCELLED_OP`): the user cancelled inside AutoFirma itself.
// - AS620017 / AS620020 / AS620025: AutoFirma could not be reached after
//   the client's own retry budget (`AUTOFIRMA_CONNECTION_RETRIES`) was
//   exhausted -- reported as `es.gob.afirma.standalone.ApplicationNotFoundException`.
// A fourth "invalid document" bucket is best-effort: AutoFirma's own
// document-parsing exceptions are Java exceptions thrown by the native
// application, not enumerated anywhere in this JS-side library, so they
// are recognized here by their exception name only when it clearly names a
// format/document problem; everything else falls through to the generic
// case, which still shows the real exception type and message so the user
// (or a support request) is never left with no information at all.
// ---------------------------------------------------------------------

const CANCELLED_EXCEPTION = "es.gob.afirma.core.AOCancelledOperationException";
const CANCELLED_CODES = new Set(["AS500001"]);

const APP_UNREACHABLE_EXCEPTION = "es.gob.afirma.standalone.ApplicationNotFoundException";
const APP_UNREACHABLE_CODES = new Set(["AS620017", "AS620020", "AS620025"]);

const INVALID_DOCUMENT_EXCEPTION_PATTERN = /InvalidFormat|FormatFile|InvalidPdf|BadPdf/i;

function describeSignError(exceptionType, errorMessage, errorCode) {
  if (exceptionType === CANCELLED_EXCEPTION || CANCELLED_CODES.has(errorCode)) {
    return "Has cancelado la operación de firma.";
  }
  if (exceptionType === APP_UNREACHABLE_EXCEPTION || APP_UNREACHABLE_CODES.has(errorCode)) {
    return (
      "No se pudo conectar con AutoFirma. Comprueba que está instalado y en ejecución en este equipo, " +
      `y vuelve a intentarlo. Si no lo tienes instalado, descárgalo desde ${AUTOFIRMA_DOWNLOAD_URL}.`
    );
  }
  if (INVALID_DOCUMENT_EXCEPTION_PATTERN.test(exceptionType || "")) {
    return "AutoFirma no pudo firmar este documento porque no es un PDF válido.";
  }
  const detail = errorMessage || "error desconocido";
  const code = errorCode ? ` (${errorCode})` : "";
  return `No se pudo firmar el documento${code}: ${detail}`;
}

// ---------------------------------------------------------------------
// Result actions: download / validate
// ---------------------------------------------------------------------

downloadButton.addEventListener("click", () => {
  if (!signedBlob) return;
  downloadBlob(signedBlob, signedFileName);
});

validateButton.addEventListener("click", () => {
  if (!signedBlob || isAnalyzing()) return;
  const signedFile = new File([signedBlob], signedFileName, { type: "application/pdf" });
  // T11e: analyzeFile() renders into the shared #results-panel, but that
  // panel sits under the Validar tab -- without switching there first, the
  // result would render invisibly behind the still-active Firmar panel.
  // Moving focus to the results heading (and scrolling it into view) makes
  // the "Validar este PDF" outcome noticeable for both sighted and
  // keyboard/screen-reader users; the verdict banner's own
  // `aria-live="polite"` (index.html) announces the actual result text once
  // renderReport() fills it in.
  switchTab("validar");
  void analyzeFile(signedFile, false).then(() => {
    // On failure resultsPanel stays hidden (analyzeFile's own error path);
    // the now-visible Validar error banner (role="alert", aria-live) already
    // announces itself, so there is nothing focusable to move to here.
    if (resultsPanel.hidden) return;
    const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    resultsHeading.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    resultsHeading.focus();
  });
});

// ---------------------------------------------------------------------
// UI state helpers
// ---------------------------------------------------------------------

function setWaiting(waiting) {
  firmarButton.disabled = waiting || !selectedFile;
  firmarSpinner.hidden = !waiting;
  waitingPanel.hidden = !waiting;
  dropzone.setAttribute("aria-disabled", String(waiting));
  statusLine.textContent = waiting ? "" : statusLine.textContent;
  if (waiting) {
    waitingText.textContent = "Esperando a AutoFirma… elige tu certificado en la ventana de AutoFirma.";
  }
}

function hideResult() {
  resultPanel.hidden = true;
  signedBlob = null;
  signedFileName = null;
}

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.hidden = false;
}

function clearError() {
  errorBanner.hidden = true;
  errorBanner.textContent = "";
}
