package com.coam.pdfvalidator.domain.model;

import java.util.Objects;

/**
 * Records that {@code section} failed unexpectedly while an analysis was
 * running, so {@link PdfAnalysisReport#sectionErrors()} can say so
 * explicitly.
 *
 * <p><b>Why this exists (T08b)</b>: before this, an unexpected failure of
 * e.g. the signature verifier degraded to an empty {@code signatures} list --
 * indistinguishable from a document that legitimately has no signatures at
 * all. A caller (the future UI, or anyone reading the JSON report) had no way
 * to tell "this document is unsigned" apart from "signature verification
 * itself blew up and we don't actually know". Every {@link AnalysisSection}
 * that is guarded against an unexpected {@code RuntimeException} now also
 * appends one of these instead of only degrading silently.
 */
public record SectionError(AnalysisSection section, String message) {

    public SectionError {
        Objects.requireNonNull(section, "section");
        Objects.requireNonNull(message, "message");
    }
}
