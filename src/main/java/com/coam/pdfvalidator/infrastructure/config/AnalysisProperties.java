package com.coam.pdfvalidator.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Concurrency limit for PDF analyses (T12c bulkhead).
 *
 * @param maxConcurrent  maximum analyses running at once (default 2)
 * @param acquireTimeout how long a request waits for a slot before a 503 (default 5 s)
 */
@ConfigurationProperties(prefix = "pdfvalidator.analysis")
public record AnalysisProperties(
        @DefaultValue("2") int maxConcurrent,
        @DefaultValue("5s") Duration acquireTimeout) {
}
