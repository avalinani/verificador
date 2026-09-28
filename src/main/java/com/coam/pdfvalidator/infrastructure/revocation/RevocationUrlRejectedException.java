package com.coam.pdfvalidator.infrastructure.revocation;

/**
 * Thrown by {@link RevocationUrlGuard} when an OCSP/CRL distribution point
 * URL fails the SSRF guard: an unsupported scheme, or a host resolving to a
 * private/loopback/link-local address while that is not explicitly allowed
 * (test-only). Always caught internally by {@link OcspClient}/{@link
 * CrlClient} and turned into a {@code RevocationState.UNKNOWN} result --
 * never allowed to escape and abort the rest of the analysis.
 */
final class RevocationUrlRejectedException extends RuntimeException {

    RevocationUrlRejectedException(String message) {
        super(message);
    }
}
