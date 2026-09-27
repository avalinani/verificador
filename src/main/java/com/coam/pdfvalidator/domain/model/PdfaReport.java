package com.coam.pdfvalidator.domain.model;

import java.util.List;
import java.util.Objects;

/** Result of validating a PDF against PDF/A-1b. */
public record PdfaReport(PdfaDeclaration declaration, PdfaValidationStatus status, List<PdfaIssue> issues) {

    public PdfaReport {
        Objects.requireNonNull(declaration, "declaration");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(issues, "issues");
        issues = List.copyOf(issues);
    }
}
