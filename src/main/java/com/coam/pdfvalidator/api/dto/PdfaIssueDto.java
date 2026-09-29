package com.coam.pdfvalidator.api.dto;

/**
 * A single PDF/A conformance violation. {@code message} is PDFBox's own
 * (English) description; {@code messageEs} is a neutral, professional
 * Spanish translation of it for the web UI, looked up by {@code code} via
 * {@code domain.model.PdfaIssueCatalog} -- {@code null} when this catalog
 * does not recognize {@code code} (T11g), in which case the UI shows only
 * the original English message.
 */
public record PdfaIssueDto(String code, String message, String messageEs) {
}
