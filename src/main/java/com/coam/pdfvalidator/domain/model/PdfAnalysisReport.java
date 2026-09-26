package com.coam.pdfvalidator.domain.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** The complete, single-pass audit result for one PDF file. */
public record PdfAnalysisReport(
        String fileName,
        long sizeBytes,
        DocumentHashes hashes,
        DocumentStructure structure,
        SecurityInfo security,
        PdfaReport pdfa,
        List<SignatureReport> signatures,
        Instant analyzedAt) {

    public PdfAnalysisReport {
        Objects.requireNonNull(fileName, "fileName");
        Objects.requireNonNull(hashes, "hashes");
        Objects.requireNonNull(structure, "structure");
        Objects.requireNonNull(security, "security");
        Objects.requireNonNull(pdfa, "pdfa");
        Objects.requireNonNull(signatures, "signatures");
        Objects.requireNonNull(analyzedAt, "analyzedAt");
        signatures = List.copyOf(signatures);
        if (sizeBytes < 0) {
            throw new IllegalArgumentException("sizeBytes must be >= 0, got: " + sizeBytes);
        }
    }
}
