package com.coam.pdfvalidator.infrastructure.revocation;

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * A point in time by which some revocation work must be finished. One
 * {@code Deadline} is created per signature's whole revocation check and
 * shared by every OCSP and CRL attempt across all certificates of the path,
 * so the total time (and network egress) is bounded no matter how many
 * AIA/CDP URLs the certificates declare; each single attempt additionally
 * runs under {@link #capped a per-request cap}.
 *
 * <p>The clock is injectable ({@code System::nanoTime} in production) so the
 * budget logic can be tested deterministically without sleeping.
 */
final class Deadline {

    /** Stable {@code detail} of an attempt that was not made because the shared budget was already spent. */
    static final String EXHAUSTED_DETAIL = "revocation time budget exhausted";

    private final LongSupplier nanoClock;
    private final long expiresAtNanos;

    private Deadline(LongSupplier nanoClock, long expiresAtNanos) {
        this.nanoClock = nanoClock;
        this.expiresAtNanos = expiresAtNanos;
    }

    static Deadline after(Duration budget, LongSupplier nanoClock) {
        return new Deadline(nanoClock, nanoClock.getAsLong() + budget.toNanos());
    }

    static Deadline after(Duration budget) {
        return after(budget, System::nanoTime);
    }

    /** Time left, never negative. */
    Duration remaining() {
        long left = expiresAtNanos - nanoClock.getAsLong();
        return left <= 0 ? Duration.ZERO : Duration.ofNanos(left);
    }

    boolean expired() {
        return expiresAtNanos - nanoClock.getAsLong() <= 0;
    }

    /** A deadline that expires at {@code cap} from now, or at this one, whichever comes first. */
    Deadline capped(Duration cap) {
        long capped = nanoClock.getAsLong() + cap.toNanos();
        return new Deadline(nanoClock, Math.min(capped, expiresAtNanos));
    }
}
