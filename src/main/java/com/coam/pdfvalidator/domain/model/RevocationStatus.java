package com.coam.pdfvalidator.domain.model;

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
}
