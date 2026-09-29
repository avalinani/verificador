package com.coam.pdfvalidator.api.concurrency;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AnalysisBulkheadTest {

    @Test
    void grantsUpToMaxConcurrentPermitsAndRejectsTheNext() {
        AnalysisBulkhead bulkhead = new AnalysisBulkhead(2, Duration.ofMillis(20));

        try (AnalysisBulkhead.Permit first = bulkhead.acquire();
                AnalysisBulkhead.Permit second = bulkhead.acquire()) {
            assertThat(first).isNotNull();
            assertThat(second).isNotNull();
            assertThat(bulkhead.availablePermits()).isZero();
            assertThatThrownBy(bulkhead::acquire).isInstanceOf(AnalysisBusyException.class);
        }
    }

    @Test
    void closingAPermitMakesItAvailableAgain() {
        AnalysisBulkhead bulkhead = new AnalysisBulkhead(1, Duration.ofMillis(20));

        bulkhead.acquire().close();

        assertThat(bulkhead.availablePermits()).isEqualTo(1);
        bulkhead.acquire().close();
    }

    @Test
    void closingAPermitTwiceReleasesOnlyOnce() {
        AnalysisBulkhead bulkhead = new AnalysisBulkhead(1, Duration.ofMillis(20));

        AnalysisBulkhead.Permit permit = bulkhead.acquire();
        permit.close();
        permit.close();

        assertThat(bulkhead.availablePermits()).isEqualTo(1);
    }

    @Test
    void thePermitIsReleasedWhenTheGuardedWorkThrows() {
        AnalysisBulkhead bulkhead = new AnalysisBulkhead(1, Duration.ofMillis(20));

        assertThatThrownBy(() -> {
            try (AnalysisBulkhead.Permit ignored = bulkhead.acquire()) {
                throw new IllegalStateException("boom");
            }
        }).isInstanceOf(IllegalStateException.class);

        assertThat(bulkhead.availablePermits()).isEqualTo(1);
    }

    @Test
    void aWaitingCallerGetsThePermitWhenItIsReleasedWithinTheTimeout() throws Exception {
        AnalysisBulkhead bulkhead = new AnalysisBulkhead(1, Duration.ofSeconds(5));
        AnalysisBulkhead.Permit held = bulkhead.acquire();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            CountDownLatch waiting = new CountDownLatch(1);
            Future<Boolean> second = executor.submit(() -> {
                waiting.countDown();
                try (AnalysisBulkhead.Permit ignored = bulkhead.acquire()) {
                    return true;
                }
            });
            assertThat(waiting.await(2, TimeUnit.SECONDS)).isTrue();
            held.close();

            assertThat(second.get(3, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void theBusyExceptionAdvertisesTheTimeoutAsRetryAfterWithAOneSecondFloor() {
        AnalysisBulkhead slow = new AnalysisBulkhead(1, Duration.ofSeconds(5));
        AnalysisBulkhead fast = new AnalysisBulkhead(1, Duration.ofMillis(10));

        try (AnalysisBulkhead.Permit ignored = fast.acquire()) {
            assertThatThrownBy(fast::acquire)
                    .isInstanceOfSatisfying(AnalysisBusyException.class,
                            e -> assertThat(e.retryAfterSeconds()).isEqualTo(1));
        }
        try (AnalysisBulkhead.Permit ignored = slow.acquire()) {
            assertThat(slow.retryAfterSeconds()).isEqualTo(5);
        }
    }

    @Test
    void anInterruptedWaiterIsRejectedAsBusyAndKeepsItsInterruptFlag() {
        AnalysisBulkhead bulkhead = new AnalysisBulkhead(1, Duration.ofSeconds(5));
        try (AnalysisBulkhead.Permit ignored = bulkhead.acquire()) {
            Thread.currentThread().interrupt();
            assertThatThrownBy(bulkhead::acquire).isInstanceOf(AnalysisBusyException.class);
            assertThat(Thread.interrupted()).isTrue();
        }
    }

    @Test
    void rejectsNonPositiveConfiguration() {
        assertThatThrownBy(() -> new AnalysisBulkhead(0, Duration.ofSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AnalysisBulkhead(1, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
