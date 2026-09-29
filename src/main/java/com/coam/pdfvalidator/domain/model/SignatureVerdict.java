package com.coam.pdfvalidator.domain.model;

/**
 * Overall admissibility verdict for one PDF signature (T11 -- README section
 * on the "Validar" screen), combining {@link IntegrityStatus}, {@link
 * ChainStatus} and {@link RevocationStatus} into the single answer the UI
 * asks: <em>is this signature valid?</em> Computed by {@code
 * com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy}; see that
 * class's Javadoc for the full decision table.
 */
public enum SignatureVerdict {
    /** Integrity intact, chain trusted, and revocation either good or legitimately not requested. */
    VALID,
    /**
     * Integrity intact (or covered by a later signature), but something
     * about trust could not be positively confirmed: an untrusted/incomplete/
     * expired chain, an unsupported signature format, or revocation that was
     * requested but came back unknown/unavailable.
     */
    NOT_ADMITTED,
    /** The signature itself is cryptographically invalid, revoked, or the document was modified after it with no later signature covering that change. */
    INVALID
}
