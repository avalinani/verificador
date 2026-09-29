package com.coam.pdfvalidator.domain.model;

/**
 * A section of {@code com.coam.pdfvalidator.application.AnalyzePdfUseCase}'s
 * analysis pipeline that is guarded against an unexpected failure of its own
 * adapter, so one section misbehaving cannot silently look like a legitimate
 * empty result (see {@link SectionError}).
 */
public enum AnalysisSection {
    PDFA,
    SIGNATURES
}
