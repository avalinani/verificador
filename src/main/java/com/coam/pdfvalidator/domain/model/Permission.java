package com.coam.pdfvalidator.domain.model;

/** A permission grantable (or revocable) through PDF standard security handler flags. */
public enum Permission {
    PRINT,
    MODIFY,
    EXTRACT_CONTENT,
    ANNOTATE,
    FILL_FORMS,
    EXTRACT_FOR_ACCESSIBILITY,
    ASSEMBLE,
    PRINT_HIGH_QUALITY
}
