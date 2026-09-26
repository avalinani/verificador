package com.coam.pdfvalidator.domain.model;

import java.util.Optional;

/**
 * A PDF/A conformance declaration read from the document's XMP metadata
 * ({@code pdfaid:part} / {@code pdfaid:conformance}), or the absence of one.
 * Both fields are nullable together: use {@link #NONE} rather than
 * constructing a partially-null instance.
 */
public record PdfaDeclaration(Integer part, String conformance) {

    /** No {@code pdfaid} metadata found in the document. */
    public static final PdfaDeclaration NONE = new PdfaDeclaration(null, null);

    public boolean isDeclared() {
        return part != null && conformance != null;
    }

    public Optional<Integer> declaredPart() {
        return Optional.ofNullable(part);
    }

    public Optional<String> declaredConformance() {
        return Optional.ofNullable(conformance);
    }
}
