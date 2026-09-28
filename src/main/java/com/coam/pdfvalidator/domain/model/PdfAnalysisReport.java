package com.coam.pdfvalidator.domain.model;

import com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * The complete, single-pass audit result for one PDF file.
 *
 * @param sectionErrors unexpected failures of an otherwise-guarded analysis
 *                       section (T08b), e.g. the signature verifier itself
 *                       throwing -- so an empty {@code signatures} list
 *                       caused by that failure is never silently
 *                       indistinguishable from "this document has no
 *                       signatures". Empty when every section completed
 *                       normally.
 */
public record PdfAnalysisReport(
        String fileName,
        long sizeBytes,
        DocumentHashes hashes,
        DocumentStructure structure,
        SecurityInfo security,
        PdfaReport pdfa,
        List<SignatureReport> signatures,
        Instant analyzedAt,
        List<SectionError> sectionErrors) {

    public PdfAnalysisReport {
        Objects.requireNonNull(fileName, "fileName");
        Objects.requireNonNull(hashes, "hashes");
        Objects.requireNonNull(structure, "structure");
        Objects.requireNonNull(security, "security");
        Objects.requireNonNull(pdfa, "pdfa");
        Objects.requireNonNull(signatures, "signatures");
        Objects.requireNonNull(analyzedAt, "analyzedAt");
        Objects.requireNonNull(sectionErrors, "sectionErrors");
        signatures = List.copyOf(signatures);
        sectionErrors = List.copyOf(sectionErrors);
        if (sizeBytes < 0) {
            throw new IllegalArgumentException("sizeBytes must be >= 0, got: " + sizeBytes);
        }
    }

    /**
     * The document-level summary verdict (T11): the worst of every {@link
     * SignatureReport#verdict()} in {@link #signatures()}, or {@link
     * OverallVerdict#NO_SIGNATURES} for an unsigned document. Computed
     * on demand rather than stored as its own record component -- unlike
     * {@code pageCount} on {@link DocumentStructure}, this value is never
     * independently constructed or deserialized, only ever derived from
     * {@code signatures}, so storing it separately would only add a way for
     * the two to drift out of sync without ever needing to round-trip on
     * its own.
     */
    public OverallVerdict overallVerdict() {
        return SignatureVerdictPolicy.overallVerdict(signatures);
    }

    /**
     * True when this document has at least one signature and none of them
     * cover the file all the way to its true end -- see {@link
     * SignatureVerdictPolicy#documentModifiedAfterLastSignature} for exactly
     * what this does and does not prove. Computed on demand, same rationale
     * as {@link #overallVerdict()}.
     */
    public boolean modifiedAfterLastSignature() {
        return SignatureVerdictPolicy.documentModifiedAfterLastSignature(signatures);
    }
}
