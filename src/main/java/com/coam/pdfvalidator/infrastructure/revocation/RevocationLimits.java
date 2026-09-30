package com.coam.pdfvalidator.infrastructure.revocation;

import java.time.Duration;

/**
 * Every bound on the optional revocation check (README sections 2.8 and 4,
 * {@code pdfvalidator.revocation.*}).
 *
 * @param timeout            cap for one single request (DNS lookup + connect + response), per URL
 * @param totalTimeout       one shared deadline for the whole revocation check of a signature: every
 *                           OCSP and CRL attempt for every certificate of the path
 * @param maxResponseBytes   maximum accepted response body
 * @param maxUrlsPerMethod   URLs tried per certificate and method (OCSP, CRL) after de-duplication
 * @param maxHeaderLineBytes maximum length of one HTTP line (status, header, chunk size, trailer)
 * @param maxHeaderCount     maximum number of response headers (and, separately, chunk trailers)
 * @param maxHeaderBytes     maximum combined size of the response headers (and of the trailers)
 */
public record RevocationLimits(
        Duration timeout,
        Duration totalTimeout,
        long maxResponseBytes,
        int maxUrlsPerMethod,
        int maxHeaderLineBytes,
        int maxHeaderCount,
        int maxHeaderBytes) {

    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(2);
    public static final Duration DEFAULT_TOTAL_TIMEOUT = Duration.ofSeconds(6);
    public static final long DEFAULT_MAX_RESPONSE_BYTES = 10L * 1024 * 1024;
    public static final int DEFAULT_MAX_URLS_PER_METHOD = 3;
    public static final int DEFAULT_MAX_HEADER_LINE_BYTES = 8 * 1024;
    public static final int DEFAULT_MAX_HEADER_COUNT = 100;
    public static final int DEFAULT_MAX_HEADER_BYTES = 64 * 1024;

    public RevocationLimits {
        if (timeout == null || timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("pdfvalidator.revocation.timeout must be positive");
        }
        if (totalTimeout == null || totalTimeout.isZero() || totalTimeout.isNegative()) {
            throw new IllegalArgumentException("pdfvalidator.revocation.total-timeout must be positive");
        }
        if (maxResponseBytes < 1 || maxUrlsPerMethod < 1 || maxHeaderLineBytes < 1
                || maxHeaderCount < 1 || maxHeaderBytes < 1) {
            throw new IllegalArgumentException("pdfvalidator.revocation limits must be positive");
        }
    }

    /** The documented defaults, with the given single-request timeout and response cap. */
    static RevocationLimits withDefaults(Duration timeout, long maxResponseBytes) {
        return new RevocationLimits(timeout, DEFAULT_TOTAL_TIMEOUT, maxResponseBytes,
                DEFAULT_MAX_URLS_PER_METHOD, DEFAULT_MAX_HEADER_LINE_BYTES,
                DEFAULT_MAX_HEADER_COUNT, DEFAULT_MAX_HEADER_BYTES);
    }

    PinnedHttpClient.Limits httpLimits() {
        return new PinnedHttpClient.Limits(maxHeaderLineBytes, maxHeaderCount, maxHeaderBytes);
    }
}
