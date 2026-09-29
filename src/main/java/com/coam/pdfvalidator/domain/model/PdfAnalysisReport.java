package com.coam.pdfvalidator.domain.model;

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
}
