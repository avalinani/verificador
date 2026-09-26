package com.coam.pdfvalidator.domain.model;

/** Outcome of validating a PDF against the declared (or requested) PDF/A conformance level. */
public enum PdfaValidationStatus {
    COMPLIANT,
    NON_COMPLIANT,
    NOT_VALIDATED
}
