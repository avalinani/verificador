package com.coam.pdfvalidator.domain.model;

import java.util.List;
import java.util.Objects;

/**
 * A signature's {@code /ByteRange}: exactly two ranges, {@code [start1, len1,
 * start2, len2]}, covering everything except the {@code /Contents}
 * placeholder. Validates the shape every conformant signature must have: the
 * first range starts at 0, the two ranges do not overlap, and neither
 * extends past the file length.
 */
public record ByteRangeCoverage(List<Long> ranges, long fileLength) {

    public ByteRangeCoverage {
        Objects.requireNonNull(ranges, "ranges");
        ranges = List.copyOf(ranges);
        if (ranges.size() != 4) {
            throw new IllegalArgumentException("ByteRange must have exactly 4 values, got: " + ranges.size());
        }
        if (fileLength < 0) {
            throw new IllegalArgumentException("fileLength must be >= 0, got: " + fileLength);
        }
        long start1 = ranges.get(0);
        long len1 = ranges.get(1);
        long start2 = ranges.get(2);
        long len2 = ranges.get(3);
        // A hostile PDF can carry arbitrary /ByteRange values: reject negative
        // offsets/lengths up front so the arithmetic below cannot be fooled by them.
        if (start1 < 0 || len1 < 0 || start2 < 0 || len2 < 0) {
            throw new IllegalArgumentException("ByteRange values must not be negative, got: " + ranges);
        }
        if (start1 != 0) {
            throw new IllegalArgumentException("ByteRange must start at 0, got: " + start1);
        }
        long firstRangeEnd;
        try {
            firstRangeEnd = Math.addExact(start1, len1);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(
                    "ByteRange first range overflows: start=" + start1 + ", length=" + len1, e);
        }
        if (start2 < firstRangeEnd) {
            throw new IllegalArgumentException(
                    "ByteRange ranges must not overlap: first range ends at " + firstRangeEnd
                            + ", second range starts at " + start2);
        }
        long secondRangeEnd;
        try {
            secondRangeEnd = Math.addExact(start2, len2);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(
                    "ByteRange second range overflows: start=" + start2 + ", length=" + len2, e);
        }
        if (secondRangeEnd > fileLength) {
            throw new IllegalArgumentException(
                    "ByteRange must not exceed the file length: covers up to " + secondRangeEnd
                            + ", file length is " + fileLength);
        }
    }

    public static ByteRangeCoverage of(long start1, long len1, long start2, long len2, long fileLength) {
        return new ByteRangeCoverage(List.of(start1, len1, start2, len2), fileLength);
    }

    /**
     * Placeholder used when a signature's raw {@code /ByteRange} is
     * structurally invalid (hostile or malformed) and the four raw values
     * cannot themselves be reported as a valid coverage. Reports zero
     * coverage over a file of the given length rather than the unusable raw
     * values, while still satisfying this record's own invariants.
     */
    public static ByteRangeCoverage unknown(long fileLength) {
        return new ByteRangeCoverage(List.of(0L, 0L, 0L, 0L), fileLength);
    }

    /** Offset right after the second (final) signed range. */
    public long signedRevisionEnd() {
        return ranges.get(2) + ranges.get(3);
    }

    /** True when the signed ranges reach the end of the file, i.e. nothing was appended after signing. */
    public boolean coversWholeDocument() {
        return signedRevisionEnd() == fileLength;
    }
}
