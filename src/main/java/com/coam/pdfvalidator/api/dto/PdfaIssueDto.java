package com.coam.pdfvalidator.api.dto;

/** A single PDF/A conformance violation. */
public record PdfaIssueDto(String code, String message) {
}
