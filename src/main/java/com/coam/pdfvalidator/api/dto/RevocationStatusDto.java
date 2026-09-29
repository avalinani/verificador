package com.coam.pdfvalidator.api.dto;

/**
 * Result of an (optional) revocation check for one signer certificate.
 *
 * @param state  {@code "GOOD"}, {@code "REVOKED"}, {@code "UNKNOWN"} or
 *               {@code "NOT_CHECKED"} (the flag was off, or a real checker
 *               is not available yet -- see {@code detail})
 * @param source the OCSP responder or CRL distribution point URL that
 *               produced this result, or {@code null}
 * @param detail a human-readable explanation (e.g. a timeout/failure
 *               reason), or {@code null}
 */
public record RevocationStatusDto(String state, String source, String detail) {
}
