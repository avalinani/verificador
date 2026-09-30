package com.coam.pdfvalidator.domain.model;

import java.util.List;
import java.util.Objects;

/**
 * Result of a revocation check: the resulting {@link RevocationState}, which
 * source produced it (e.g. an OCSP responder or CRL distribution point URL),
 * and any human-readable detail (e.g. the failure reason on {@code UNKNOWN}).
 */
public record RevocationStatus(RevocationState state, String source, String detail) {

    public RevocationStatus {
        Objects.requireNonNull(state, "state");
    }

    /** Revocation was not checked at all (feature disabled, or not yet enriched). */
    public static RevocationStatus notChecked() {
        return new RevocationStatus(RevocationState.NOT_CHECKED, null, null);
    }

    /**
     * Folds the per-certificate results of one certification path into the
     * single status reported for the signature. {@code checked.get(i)} is the
     * certificate whose result is {@code results.get(i)}; index 0 is the
     * signer (leaf), the following ones its issuers up to (excluding) the
     * trust anchor.
     *
     * <ul>
     *   <li>any {@code REVOKED} wins (the first one): the path is revoked;</li>
     *   <li>otherwise any result that is not {@code GOOD} (unknown,
     *       unavailable, not checked) makes the path inconclusive -- the
     *       first such result is reported, fail-closed;</li>
     *   <li>only when every result is {@code GOOD} is the path {@code GOOD}
     *       (reported with the signer's own result).</li>
     * </ul>
     *
     * The signer's result is returned untouched (stable text); a result
     * caused by a CA certificate is prefixed with that certificate's subject
     * so the report says which certificate is at fault.
     */
    public static RevocationStatus aggregate(List<CertificateInfo> checked, List<RevocationStatus> results) {
        if (checked.size() != results.size() || results.isEmpty()) {
            throw new IllegalArgumentException("one revocation result per checked certificate is required");
        }
        int culprit = firstIndexOf(results, RevocationState.REVOKED);
        if (culprit < 0) {
            culprit = firstNotGood(results);
        }
        if (culprit < 0) {
            return results.get(0);
        }
        RevocationStatus result = results.get(culprit);
        if (culprit == 0) {
            return result;
        }
        String subject = "CA certificate '" + checked.get(culprit).subject() + "'";
        String detail = result.detail() == null ? subject : subject + ": " + result.detail();
        return new RevocationStatus(result.state(), result.source(), detail);
    }

    private static int firstIndexOf(List<RevocationStatus> results, RevocationState state) {
        for (int i = 0; i < results.size(); i++) {
            if (results.get(i).state() == state) {
                return i;
            }
        }
        return -1;
    }

    private static int firstNotGood(List<RevocationStatus> results) {
        for (int i = 0; i < results.size(); i++) {
            if (results.get(i).state() != RevocationState.GOOD) {
                return i;
            }
        }
        return -1;
    }
}
