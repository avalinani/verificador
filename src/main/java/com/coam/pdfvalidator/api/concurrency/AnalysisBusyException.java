package com.coam.pdfvalidator.api.concurrency;

/**
 * No analysis permit became available within the acquire timeout: the service
 * is saturated. Mapped to {@code 503} + {@code Retry-After} by {@code
 * AnalysisBusyExceptionHandler}.
 */
public class AnalysisBusyException extends RuntimeException {

    private final long retryAfterSeconds;

    public AnalysisBusyException(long retryAfterSeconds) {
        super("All analysis slots are busy");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    /** Suggested client back-off, in seconds (value of the {@code Retry-After} header). */
    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
