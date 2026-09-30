package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.infrastructure.config.RevocationProperties;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** T21: the shared deadline arithmetic and the configurable bounds (defaults and validation). */
class DeadlineAndLimitsTest {

    @Test
    void remainingTimeShrinksWithTheClockAndNeverGoesNegative() {
        AtomicLong clock = new AtomicLong(0);
        Deadline deadline = Deadline.after(Duration.ofSeconds(6), clock::get);

        assertThat(deadline.remaining()).isEqualTo(Duration.ofSeconds(6));
        assertThat(deadline.expired()).isFalse();

        clock.addAndGet(Duration.ofSeconds(4).toNanos());
        assertThat(deadline.remaining()).isEqualTo(Duration.ofSeconds(2));

        clock.addAndGet(Duration.ofSeconds(10).toNanos());
        assertThat(deadline.remaining()).isEqualTo(Duration.ZERO);
        assertThat(deadline.expired()).isTrue();
    }

    @Test
    void aCappedDeadlineNeverOutlivesItsParent() {
        AtomicLong clock = new AtomicLong(0);
        Deadline parent = Deadline.after(Duration.ofSeconds(6), clock::get);

        assertThat(parent.capped(Duration.ofSeconds(2)).remaining()).isEqualTo(Duration.ofSeconds(2));

        clock.addAndGet(Duration.ofSeconds(5).toNanos());
        assertThat(parent.capped(Duration.ofSeconds(2)).remaining()).isEqualTo(Duration.ofSeconds(1));
    }

    @Test
    void theSystemClockOverloadStartsWithAlmostTheWholeBudget() {
        assertThat(Deadline.after(Duration.ofSeconds(30)).remaining()).isGreaterThan(Duration.ofSeconds(29));
    }

    @Test
    void nonPositiveBoundsAreRejectedAtStartup() {
        assertThatThrownBy(() -> new RevocationLimits(Duration.ZERO, Duration.ofSeconds(6), 1, 3, 8192, 100, 65536))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("timeout");
        assertThatThrownBy(() -> new RevocationLimits(Duration.ofSeconds(2), Duration.ofSeconds(-1), 1, 3, 8192, 100, 65536))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("total-timeout");
        assertThatThrownBy(() -> new RevocationLimits(Duration.ofSeconds(2), Duration.ofSeconds(6), 1, 0, 8192, 100, 65536))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void propertiesDefaultToTheDocumentedValues() {
        RevocationLimits limits = bind(Map.of()).toLimits();

        assertThat(limits.timeout()).isEqualTo(Duration.ofSeconds(2));
        assertThat(limits.totalTimeout()).isEqualTo(Duration.ofSeconds(6));
        assertThat(limits.maxResponseBytes()).isEqualTo(10L * 1024 * 1024);
        assertThat(limits.maxUrlsPerMethod()).isEqualTo(3);
        assertThat(limits.maxHeaderLineBytes()).isEqualTo(8 * 1024);
        assertThat(limits.maxHeaderCount()).isEqualTo(100);
        assertThat(limits.maxHeaderBytes()).isEqualTo(64 * 1024);
    }

    @Test
    void propertiesCanBeOverriddenUnderThePdfvalidatorRevocationPrefix() {
        RevocationLimits limits = bind(Map.of(
                "pdfvalidator.revocation.timeout", "1s",
                "pdfvalidator.revocation.total-timeout", "4s",
                "pdfvalidator.revocation.max-urls-per-method", "2",
                "pdfvalidator.revocation.max-header-line-bytes", "4KB",
                "pdfvalidator.revocation.max-headers", "50",
                "pdfvalidator.revocation.max-header-bytes", "16KB")).toLimits();

        assertThat(limits.timeout()).isEqualTo(Duration.ofSeconds(1));
        assertThat(limits.totalTimeout()).isEqualTo(Duration.ofSeconds(4));
        assertThat(limits.maxUrlsPerMethod()).isEqualTo(2);
        assertThat(limits.maxHeaderLineBytes()).isEqualTo(4 * 1024);
        assertThat(limits.maxHeaderCount()).isEqualTo(50);
        assertThat(limits.maxHeaderBytes()).isEqualTo(16 * 1024);
    }

    private static RevocationProperties bind(Map<String, String> source) {
        return new Binder(new MapConfigurationPropertySource(source))
                .bindOrCreate("pdfvalidator.revocation", RevocationProperties.class);
    }
}
