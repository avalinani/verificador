package com.coam.pdfvalidator.api.dto;

import java.util.List;

/**
 * Result of validating the PDF against PDF/A-1b, combined with its own XMP
 * declaration.
 *
 * @param status {@code "COMPLIANT"}, {@code "NON_COMPLIANT"} or {@code
 *               "NOT_VALIDATED"} (e.g. the document declares PDF/A-2/3,
 *               which this service does not formally validate -- see {@code
 *               issues} for the {@code PDFA_PART_NOT_SUPPORTED} code)
 */
public record PdfaReportDto(PdfaDeclarationDto declaration, String status, List<PdfaIssueDto> issues) {
}
