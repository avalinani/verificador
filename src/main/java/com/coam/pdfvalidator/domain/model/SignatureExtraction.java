package com.coam.pdfvalidator.domain.model;

import java.util.List;
import java.util.Objects;

/**
 * What a {@link com.coam.pdfvalidator.domain.port.SignatureVerifier} found in a document (T20).
 *
 * @param signatures    the signature fields that were analysed
 * @param skippedFields signature fields that hold a signature but were <em>not</em> analysed because the
 *                      verifier's resource cap was reached; when positive the analysis is incomplete, so the
 *                      document-level verdict must never be {@code VALID} (the skipped signature could be the
 *                      decisive one)
 */
public record SignatureExtraction(List<SignatureReport> signatures, int skippedFields) {

    public SignatureExtraction {
        Objects.requireNonNull(signatures, "signatures");
        signatures = List.copyOf(signatures);
        if (skippedFields < 0) {
            throw new IllegalArgumentException("skippedFields must be >= 0, got: " + skippedFields);
        }
    }
}
