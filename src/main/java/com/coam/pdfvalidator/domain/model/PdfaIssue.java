package com.coam.pdfvalidator.domain.model;

import java.util.Objects;

/** A single PDF/A conformance violation. */
public record PdfaIssue(String code, String message) {

    public PdfaIssue {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(message, "message");
    }
}
