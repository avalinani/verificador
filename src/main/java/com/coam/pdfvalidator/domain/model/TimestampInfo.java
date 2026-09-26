package com.coam.pdfvalidator.domain.model;

import java.time.Instant;

/**
 * An RFC 3161 timestamp attached to a signature, or its absence (use
 * {@link #absent()} rather than constructing a partially-null instance).
 */
public record TimestampInfo(Instant genTime, String tsaName, boolean imprintValid) {

    private static final TimestampInfo ABSENT = new TimestampInfo(null, null, false);

    public static TimestampInfo absent() {
        return ABSENT;
    }

    public boolean isPresent() {
        return genTime != null;
    }
}
