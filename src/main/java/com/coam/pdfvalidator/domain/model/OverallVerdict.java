package com.coam.pdfvalidator.domain.model;

/**
 * Document-level summary of every {@link SignatureReport#verdict()} in a
 * {@link PdfAnalysisReport} (T11): the worst of the per-signature verdicts,
 * or {@link #NO_SIGNATURES} for an unsigned document. See {@code
 * com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy#overallVerdict}.
 */
public enum OverallVerdict {
    VALID,
    NOT_ADMITTED,
    INVALID,
    /** The document has no signatures at all (not itself a validity problem). */
    NO_SIGNATURES,
    /**
     * Signature analysis itself failed unexpectedly (T11c; see {@link
     * PdfAnalysisReport#sectionErrors()} for the {@code SIGNATURES} entry) --
     * never used together with an empty {@link
     * PdfAnalysisReport#signatures()} list to mean "legitimately unsigned",
     * which is what {@link #NO_SIGNATURES} is reserved for.
     */
    ANALYSIS_INCOMPLETE
}
