package com.coam.pdfvalidator.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import org.springframework.util.unit.DataSize;

import java.time.Duration;

/**
 * Concurrency limit for PDF analyses (T12c bulkhead).
 *
 * @param maxConcurrent  maximum analyses running at once (default 1, sized for a small VM; see the README memory budget)
 * @param acquireTimeout how long a request waits for a slot before a 503 (default 5 s)
 * @param maxDecodedStreamSize maximum decoded size of one (non-image) PDF stream (default 32 MB); larger streams make
 *                       the PDF/A check report {@code DOCUMENT_TOO_COMPLEX} instead of inflating them (T18a)
 * @param maxDecodedTotalSize maximum decoded size of all streams of one PDF together (default 2 GB); bounds inflate CPU
 * @param maxPages       pages whose details are read and returned (default 1000); the total page count is still
 *                       reported and the structure is flagged {@code pagesTruncated} (T20)
 * @param maxRevisionMarkers occurrences of each revision keyword collected while counting revisions (default
 *                       1 000 000); beyond it the revision count is a lower bound (T20)
 * @param maxRevisions   cross-reference sections followed by the revision walk (default 10 000); beyond it the
 *                       revision count is a lower bound (T20)
 */
@ConfigurationProperties(prefix = "pdfvalidator.analysis")
public record AnalysisProperties(
        @DefaultValue("1") int maxConcurrent,
        @DefaultValue("5s") Duration acquireTimeout,
        @DefaultValue("32MB") DataSize maxDecodedStreamSize,
        @DefaultValue("2GB") DataSize maxDecodedTotalSize,
        @DefaultValue("1000") int maxPages,
        @DefaultValue("1000000") int maxRevisionMarkers,
        @DefaultValue("10000") int maxRevisions) {
}
