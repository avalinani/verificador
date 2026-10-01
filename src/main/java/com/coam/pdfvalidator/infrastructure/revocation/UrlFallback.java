package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;

import java.time.Duration;
import java.util.List;
import java.util.function.BiFunction;

/**
 * The URL fallback policy shared by {@link OcspClient} and {@link CrlClient}: try each distribution point in
 * order and stop at the first conclusive answer.
 */
final class UrlFallback {

    private UrlFallback() {
    }

    /**
     * Tries each URL in order, returning the first non-{@code UNKNOWN} result, or the last {@code UNKNOWN}
     * one. Every attempt runs under the smaller of {@code perAttempt} and the shared {@code deadline}; once
     * that is spent, the remaining URLs are not contacted at all.
     *
     * @param noUrlDetail the {@code UNKNOWN} detail to report when {@code urls} is empty
     * @param attempt     checks one URL under the attempt deadline it is given
     */
    static RevocationStatus firstConclusive(
            List<String> urls, Deadline deadline, Duration perAttempt, String noUrlDetail,
            BiFunction<String, Deadline, RevocationStatus> attempt) {
        RevocationStatus last = new RevocationStatus(RevocationState.UNKNOWN, null, noUrlDetail);
        for (String url : urls) {
            if (deadline.expired()) {
                return new RevocationStatus(RevocationState.UNKNOWN, null, Deadline.EXHAUSTED_DETAIL);
            }
            last = attempt.apply(url, deadline.capped(perAttempt));
            if (last.state() != RevocationState.UNKNOWN) {
                return last;
            }
        }
        return last;
    }
}
