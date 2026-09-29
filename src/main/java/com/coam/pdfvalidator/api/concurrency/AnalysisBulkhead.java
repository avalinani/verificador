package com.coam.pdfvalidator.api.concurrency;

import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Bulkhead limiting how many PDF analyses (upload buffering + analysis) run
 * at once, so worst-case memory stays inside the container budget: PDFBox and
 * preflight multiply the memory of each document, and Tomcat alone would admit
 * up to {@code server.tomcat.threads.max} of them.
 *
 * <p>At most {@code maxConcurrent} permits exist. A caller waits up to {@code
 * acquireTimeout} for one; otherwise {@link AnalysisBusyException} is thrown.
 * A {@link Permit} is an {@link AutoCloseable} released exactly once, so
 * try-with-resources guarantees release on exceptions. Fairness is not
 * required.
 */
public final class AnalysisBulkhead {

    private final Semaphore semaphore;
    private final Duration acquireTimeout;

    public AnalysisBulkhead(int maxConcurrent, Duration acquireTimeout) {
        if (maxConcurrent < 1) {
            throw new IllegalArgumentException("max-concurrent must be at least 1");
        }
        if (acquireTimeout == null || acquireTimeout.isNegative()) {
            throw new IllegalArgumentException("acquire-timeout must not be negative");
        }
        this.semaphore = new Semaphore(maxConcurrent);
        this.acquireTimeout = acquireTimeout;
    }

    /**
     * @throws AnalysisBusyException if no permit was obtained within the timeout,
     *                               or the waiting thread was interrupted (its
     *                               interrupt flag is preserved)
     */
    public Permit acquire() {
        try {
            if (semaphore.tryAcquire(acquireTimeout.toNanos(), TimeUnit.NANOSECONDS)) {
                return new Permit(semaphore);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        throw new AnalysisBusyException(retryAfterSeconds());
    }

    public int availablePermits() {
        return semaphore.availablePermits();
    }

    /** The acquire timeout in whole seconds, rounded up, never below 1. */
    long retryAfterSeconds() {
        long seconds = (acquireTimeout.toMillis() + 999) / 1000;
        return Math.max(1, seconds);
    }

    /** A held analysis slot; {@link #close()} is idempotent. */
    public static final class Permit implements AutoCloseable {

        private final Semaphore semaphore;
        private final AtomicBoolean released = new AtomicBoolean();

        private Permit(Semaphore semaphore) {
            this.semaphore = semaphore;
        }

        @Override
        public void close() {
            if (released.compareAndSet(false, true)) {
                semaphore.release();
            }
        }
    }
}
