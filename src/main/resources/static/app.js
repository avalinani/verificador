// Validador PDF -- frontend logic (vanilla ES module, no build step, no CDNs).
// Security note: every string that can come from the server (subject names,
// field names, anomaly/reason text, ...) is rendered with textContent, never
// innerHTML -- the analysis report can contain attacker-controlled strings
// extracted from the uploaded PDF itself.

const ANALYZE_URL = "/api/v1/pdf/analyze";
const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024; // must match spring.servlet.multipart.max-file-size
const THEME_STORAGE_KEY = "pdfvalidator.theme";

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

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.setAttribute("data-theme", theme);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

function currentEffectiveTheme() {
  const explicit = document.documentElement.getAttribute("data-theme");
  if (explicit) return explicit;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function initTheme() {
  const stored = readStoredTheme();
  applyTheme(stored);
  updateThemeToggleLabel();
}

function updateThemeToggleLabel() {
  const effective = currentEffectiveTheme();
  const nextLabel = effective === "dark" ? "Cambiar a tema claro" : "Cambiar a tema oscuro";
  themeToggle.setAttribute("aria-label", nextLabel);
  themeToggle.setAttribute("aria-pressed", String(effective === "dark"));
}

// ---------------------------------------------------------------------
// DOM references
// ---------------------------------------------------------------------

const themeToggle = document.getElementById("theme-toggle");
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
const resultsPanel = document.getElementById("results-panel");
const verdictBanner = document.getElementById("verdict-banner");
const sectionErrorsEl = document.getElementById("section-errors");
const signaturesList = document.getElementById("signatures-list");
const documentDetails = document.getElementById("document-details");
const downloadJsonButton = document.getElementById("download-json");
const tabValidar = document.getElementById("tab-validar");
const tabFirmar = document.getElementById("tab-firmar");

let selectedFile = null;
let lastReport = null;

// ---------------------------------------------------------------------
// File selection
// ---------------------------------------------------------------------

function formatBytes(bytes) {
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

function looksLikePdfFile(file) {
  const nameIsPdf = /\.pdf$/i.test(file.name || "");
  const typeIsPdf = file.type === "application/pdf" || file.type === "";
  return nameIsPdf && typeIsPdf;
}

function setSelectedFile(file) {
  clearError();
  if (!file) {
    selectedFile = null;
    fileChip.hidden = true;
    analyzeButton.disabled = true;
    return;
  }
  if (!looksLikePdfFile(file)) {
    showError("El archivo seleccionado no parece un PDF. Elige un archivo con extensión .pdf.");
    return;
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
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

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (event) => {
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
  const file = event.dataTransfer?.files?.[0];
  if (file) setSelectedFile(file);
});

fileInput.addEventListener("change", () => {
  setSelectedFile(fileInput.files?.[0] ?? null);
});

fileChipRemove.addEventListener("click", () => {
  fileInput.value = "";
  setSelectedFile(null);
});

// ---------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------

analyzeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selectedFile) return;
  void analyze(selectedFile, checkRevocation.checked);
});

async function analyze(file, wantsRevocationCheck) {
  setLoading(true);
  clearError();
  hideResults();

  const formData = new FormData();
  formData.append("file", file, file.name);

  const url = `${ANALYZE_URL}?checkRevocation=${wantsRevocationCheck ? "true" : "false"}`;

  let response;
  try {
    response = await fetch(url, { method: "POST", body: formData });
  } catch {
    setLoading(false);
    showError("No se pudo conectar con el servidor. Comprueba tu conexión e inténtalo de nuevo.");
    return;
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  setLoading(false);

  if (!response.ok) {
    showError(describeError(response.status, payload));
    return;
  }

  lastReport = payload;
  renderReport(payload);
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

function hideResults() {
  resultsPanel.hidden = true;
}

// ---------------------------------------------------------------------
// Reason code / enum -> Spanish text
// ---------------------------------------------------------------------

const VERDICT_TEXT = {
  VALID: { label: "Firma válida", icon: "check", cssClass: "verdict-valid" },
  NOT_ADMITTED: { label: "Firma no admitida", icon: "warning", cssClass: "verdict-not-admitted" },
  INVALID: { label: "Firma inválida", icon: "cross", cssClass: "verdict-invalid" },
  NO_SIGNATURES: { label: "Documento sin firmas", icon: "info", cssClass: "verdict-none" },
};

const SIGNATURE_VERDICT_BADGE = {
  VALID: { label: "Válida", cssClass: "badge-valid" },
  NOT_ADMITTED: { label: "No admitida", cssClass: "badge-not-admitted" },
  INVALID: { label: "Inválida", cssClass: "badge-invalid" },
};

const REASON_TEXT = {
  SIGNATURE_INVALID: "La firma criptográfica no es válida.",
  SIGNATURE_FORMAT_UNSUPPORTED: "El formato de firma no está soportado por este servicio.",
  MODIFIED_AFTER_LAST_SIGNATURE: "El documento se modificó después de esta firma y ninguna firma posterior cubre el contenido final.",
  COVERED_BY_LATER_SIGNATURE: "El documento cambió después de esta firma, pero una firma posterior válida cubre el contenido final (flujo normal de varias firmas).",
  CHAIN_UNTRUSTED_ROOT: "La cadena de certificados no llega a una entidad de confianza reconocida.",
  CHAIN_INCOMPLETE: "Falta al menos un certificado intermedio en la cadena de confianza.",
  CHAIN_EXPIRED: "Algún certificado de la cadena estaba caducado en el momento de la validación.",
  CHAIN_NOT_CHECKED: "No se pudo comprobar la cadena de confianza de esta firma.",
  REVOCATION_NOT_REQUESTED: "No se comprobó la revocación del certificado (opción desactivada).",
  REVOCATION_REVOKED: "El certificado del firmante está revocado.",
  REVOCATION_UNKNOWN: "No se pudo determinar si el certificado está revocado.",
  REVOCATION_UNAVAILABLE: "La comprobación de revocación no estuvo disponible para esta firma.",
};

const INTEGRITY_TEXT = {
  INTACT: "Íntegra",
  MODIFIED_AFTER_SIGNING: "Modificado tras la firma",
  INVALID_SIGNATURE: "Firma inválida",
  UNSUPPORTED: "Formato no soportado",
};

const CHAIN_STATUS_TEXT = {
  TRUSTED: "De confianza",
  UNTRUSTED_ROOT: "Raíz no reconocida",
  INCOMPLETE_CHAIN: "Cadena incompleta",
  EXPIRED: "Certificado caducado",
  NOT_CHECKED: "No comprobada",
};

const REVOCATION_STATE_TEXT = {
  GOOD: "No revocado",
  REVOKED: "Revocado",
  UNKNOWN: "Desconocido",
  NOT_CHECKED: "No comprobada",
};

const PDFA_STATUS_TEXT = {
  COMPLIANT: "Conforme con PDF/A-1b",
  NON_COMPLIANT: "No conforme con PDF/A-1b",
  NOT_VALIDATED: "No validado",
};

const ORIENTATION_TEXT = { PORTRAIT: "Vertical", LANDSCAPE: "Horizontal", SQUARE: "Cuadrada" };

function reasonText(code) {
  return REASON_TEXT[code] || code;
}

// ---------------------------------------------------------------------
// Rendering: verdict banner + section errors
// ---------------------------------------------------------------------

const ICONS = {
  check: '<path d="M20 6 9 17l-5-5"/>',
  warning: '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="m10.29 3.86-8.48 14.7A1 1 0 0 0 2.66 20h18.68a1 1 0 0 0 .85-1.44L13.71 3.86a1 1 0 0 0-1.72 0Z"/>',
  cross: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
};

function svgIcon(name, extraClass) {
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

function renderVerdictBanner(report) {
  verdictBanner.replaceChildren();
  const info = VERDICT_TEXT[report.overallVerdict] || VERDICT_TEXT.NO_SIGNATURES;
  verdictBanner.className = `verdict-banner ${info.cssClass}`;

  const icon = svgIcon(info.icon, "verdict-icon");
  const textWrap = document.createElement("div");

  const title = document.createElement("p");
  title.className = "verdict-title";
  title.textContent = info.label;
  textWrap.appendChild(title);

  const body = document.createElement("p");
  body.className = "verdict-body";
  body.textContent = verdictBodyText(report);
  textWrap.appendChild(body);

  verdictBanner.append(icon, textWrap);
}

function verdictBodyText(report) {
  if (report.overallVerdict === "NO_SIGNATURES") {
    return "Este documento no contiene ninguna firma electrónica.";
  }
  const count = report.signatures.length;
  const plural = count === 1 ? "firma" : "firmas";
  let text = `Se ${count === 1 ? "ha analizado" : "han analizado"} ${count} ${plural}.`;
  if (report.modifiedAfterLastSignature) {
    text += " El documento se modificó después de la última firma.";
  }
  return text;
}

function renderSectionErrors(report) {
  sectionErrorsEl.replaceChildren();
  if (!report.sectionErrors || report.sectionErrors.length === 0) {
    sectionErrorsEl.hidden = true;
    return;
  }
  sectionErrorsEl.hidden = false;
  for (const sectionError of report.sectionErrors) {
    const el = document.createElement("div");
    el.className = "section-error";
    el.textContent = `Aviso (${sectionSpanish(sectionError.section)}): ${sectionError.message}`;
    sectionErrorsEl.appendChild(el);
  }
}

function sectionSpanish(section) {
  if (section === "PDFA") return "PDF/A";
  if (section === "SIGNATURES") return "firmas";
  return section;
}

// ---------------------------------------------------------------------
// Rendering: signatures
// ---------------------------------------------------------------------

function renderSignatures(report) {
  signaturesList.replaceChildren();
  if (!report.signatures || report.signatures.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Este documento no contiene firmas electrónicas.";
    signaturesList.appendChild(empty);
    return;
  }
  report.signatures.forEach((signature, index) => {
    signaturesList.appendChild(renderSignatureCard(signature, index));
  });
}

function renderSignatureCard(signature, index) {
  const card = document.createElement("article");
  card.className = "signature-card";

  const header = document.createElement("div");
  header.className = "signature-card-header";

  const nameWrap = document.createElement("div");
  const signer = signature.chain?.[0];
  const signerName = document.createElement("p");
  signerName.className = "signature-signer";
  signerName.textContent = signer ? commonNameOf(signer.subject) : `Firma ${index + 1}`;
  const fieldName = document.createElement("p");
  fieldName.className = "signature-field-name";
  fieldName.textContent = signature.fieldName;
  nameWrap.append(signerName, fieldName);

  const badgeInfo = SIGNATURE_VERDICT_BADGE[signature.verdict] || SIGNATURE_VERDICT_BADGE.NOT_ADMITTED;
  const badge = document.createElement("span");
  badge.className = `badge ${badgeInfo.cssClass}`;
  badge.textContent = badgeInfo.label;

  header.append(nameWrap, badge);
  card.appendChild(header);

  const facts = document.createElement("div");
  facts.className = "signature-facts";
  facts.append(
    fact("Emisor", signer ? commonNameOf(signer.issuer) : "-"),
    fact("Fecha declarada", formatInstant(signature.claimedSigningTime)),
    fact("Sello de tiempo", signature.timestamp?.present ? formatInstant(signature.timestamp.genTime) : "No presente"),
    fact("Integridad", INTEGRITY_TEXT[signature.integrity] || signature.integrity),
    fact("Cadena de confianza", CHAIN_STATUS_TEXT[signature.chainStatus] || signature.chainStatus),
    fact("Revocación", REVOCATION_STATE_TEXT[signature.revocation?.state] || signature.revocation?.state || "-"),
  );
  card.appendChild(facts);

  if (signature.verdictReasons && signature.verdictReasons.length > 0) {
    const reasons = document.createElement("ul");
    reasons.className = "signature-reasons";
    for (const code of signature.verdictReasons) {
      const li = document.createElement("li");
      li.textContent = reasonText(code);
      reasons.appendChild(li);
    }
    card.appendChild(reasons);
  }

  if (signature.anomaly) {
    const anomaly = document.createElement("p");
    anomaly.className = "anomaly-note";
    anomaly.textContent = `Anomalía: ${signature.anomaly}`;
    card.appendChild(anomaly);
  }

  card.appendChild(renderSignatureDetails(signature));
  return card;
}

function fact(label, value) {
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

function renderSignatureDetails(signature) {
  const details = document.createElement("details");
  details.className = "signature-details";
  const summary = document.createElement("summary");
  summary.textContent = "Detalles técnicos";
  details.appendChild(summary);

  const body = document.createElement("div");
  body.className = "signature-details-body";

  const coverage = document.createElement("p");
  coverage.textContent = signature.coverage?.coversWholeDocument
    ? "El rango firmado cubre todo el archivo."
    : "El rango firmado no llega al final del archivo (se añadió contenido después).";
  body.appendChild(coverage);

  if (signature.chain && signature.chain.length > 0) {
    const chainHeading = document.createElement("p");
    chainHeading.className = "fact-label";
    chainHeading.textContent = "Cadena de certificados";
    body.appendChild(chainHeading);

    const list = document.createElement("ul");
    list.className = "chain-list";
    for (const certificate of signature.chain) {
      list.appendChild(renderCertificateItem(certificate));
    }
    body.appendChild(list);
  }

  details.appendChild(body);
  return details;
}

function renderCertificateItem(certificate) {
  const item = document.createElement("li");
  item.className = "chain-item";

  const subject = document.createElement("div");
  subject.className = "chain-item-subject";
  subject.textContent = certificate.subject;
  item.appendChild(subject);

  const meta = document.createElement("div");
  meta.className = "chain-item-meta";
  meta.textContent = `Emisor: ${certificate.issuer} | Validez: ${formatInstant(certificate.notBefore)} - ${formatInstant(certificate.notAfter)}`;
  item.appendChild(meta);

  const fingerprint = document.createElement("div");
  fingerprint.className = "chain-item-meta mono";
  fingerprint.textContent = `SHA-256: ${certificate.sha256Fingerprint}`;
  item.appendChild(fingerprint);

  return item;
}

function commonNameOf(distinguishedName) {
  if (!distinguishedName) return "Desconocido";
  const match = /CN=([^,]+)/.exec(distinguishedName);
  return match ? match[1] : distinguishedName;
}

// ---------------------------------------------------------------------
// Rendering: document section
// ---------------------------------------------------------------------

function renderDocumentDetails(report) {
  documentDetails.replaceChildren();
  documentDetails.append(
    renderHashesCard(report.hashes),
    renderStructureCard(report.structure),
    renderSecurityCard(report.security),
    renderPdfaCard(report.pdfa),
  );
}

function renderHashesCard(hashes) {
  const card = document.createElement("div");
  card.className = "detail-card";
  const heading = document.createElement("h4");
  heading.textContent = "Huellas del archivo";
  card.appendChild(heading);
  card.appendChild(hashRow("SHA-256", hashes.sha256));
  card.appendChild(hashRow("SHA-512", hashes.sha512));
  return card;
}

function hashRow(label, value) {
  const row = document.createElement("div");
  row.className = "hash-row";
  const labelEl = document.createElement("span");
  labelEl.className = "hash-label";
  labelEl.textContent = label;
  const valueEl = document.createElement("span");
  valueEl.className = "hash-value";
  valueEl.textContent = value;
  valueEl.title = value;
  const copyButton = document.createElement("button");
  copyButton.type = "button";
  copyButton.className = "copy-button";
  copyButton.setAttribute("aria-label", `Copiar ${label}`);
  copyButton.appendChild(svgIcon("check"));
  copyButton.addEventListener("click", () => copyToClipboard(value, copyButton));
  row.append(labelEl, valueEl, copyButton);
  return row;
}

async function copyToClipboard(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    button.dataset.copied = "true";
    setTimeout(() => delete button.dataset.copied, 1500);
  } catch {
    // Clipboard API unavailable (permissions, insecure context): fail silently.
  }
}

function renderStructureCard(structure) {
  const card = document.createElement("div");
  card.className = "detail-card";
  const heading = document.createElement("h4");
  heading.textContent = "Estructura del documento";
  card.appendChild(heading);

  card.append(
    fact("Versión PDF", structure.headerVersion || "Desconocida"),
    fact("Revisiones", String(structure.revisionCount)),
  );

  if (structure.pages && structure.pages.length > 0) {
    const table = document.createElement("table");
    table.className = "pages-table";
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    ["Página", "Rotación", "Orientación", "Tamaño"].forEach((label) => {
      const th = document.createElement("th");
      th.textContent = label;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    for (const page of structure.pages) {
      const row = document.createElement("tr");
      const cells = [
        String(page.number),
        page.rotationValid ? `${page.rawRotation}°` : `${page.rawRotation}° (no válida)`,
        ORIENTATION_TEXT[page.orientation] || page.orientation,
        `${Math.round(page.mediaBox.width)} x ${Math.round(page.mediaBox.height)}`,
      ];
      for (const value of cells) {
        const td = document.createElement("td");
        td.textContent = value;
        row.appendChild(td);
      }
      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    card.appendChild(table);
  }

  return card;
}

function renderSecurityCard(security) {
  const card = document.createElement("div");
  card.className = "detail-card";
  const heading = document.createElement("h4");
  heading.textContent = "Cifrado y permisos";
  card.appendChild(heading);

  card.appendChild(fact("Cifrado", security.encrypted ? "Sí" : "No"));

  const permissions = document.createElement("div");
  permissions.className = "permission-list";
  const list = security.permissions && security.permissions.length > 0 ? security.permissions : [];
  if (list.length === 0) {
    const chip = document.createElement("span");
    chip.className = "permission-chip";
    chip.textContent = "Sin permisos concedidos";
    permissions.appendChild(chip);
  } else {
    for (const permission of list) {
      const chip = document.createElement("span");
      chip.className = "permission-chip";
      chip.textContent = permission;
      permissions.appendChild(chip);
    }
  }
  card.appendChild(permissions);
  return card;
}

function renderPdfaCard(pdfa) {
  const card = document.createElement("div");
  card.className = "detail-card";
  const heading = document.createElement("h4");
  heading.textContent = "Conformidad PDF/A";
  card.appendChild(heading);

  card.appendChild(fact("Resultado", PDFA_STATUS_TEXT[pdfa.status] || pdfa.status));
  card.appendChild(fact(
    "Declaración XMP",
    pdfa.declaration?.declared ? `PDF/A-${pdfa.declaration.part}${pdfa.declaration.conformance}` : "No declarada",
  ));

  if (pdfa.issues && pdfa.issues.length > 0) {
    const list = document.createElement("ul");
    list.className = "pdfa-issue-list";
    for (const issue of pdfa.issues) {
      const li = document.createElement("li");
      li.textContent = `${issue.code}: ${issue.message}`;
      list.appendChild(li);
    }
    card.appendChild(list);
  }

  return card;
}

// ---------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------

function renderReport(report) {
  renderVerdictBanner(report);
  renderSectionErrors(report);
  renderSignatures(report);
  renderDocumentDetails(report);
  resultsPanel.hidden = false;
  resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function formatInstant(value) {
  if (!value) return "-";
  try {
    return new Intl.DateTimeFormat("es-ES", { dateStyle: "medium", timeStyle: "medium" }).format(new Date(value));
  } catch {
    return value;
  }
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

// ---------------------------------------------------------------------
// Theme toggle & navigation wiring
// ---------------------------------------------------------------------

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

tabFirmar.addEventListener("click", () => {
  // Disabled control; this listener only guards against a future enabled state.
});

initTheme();
