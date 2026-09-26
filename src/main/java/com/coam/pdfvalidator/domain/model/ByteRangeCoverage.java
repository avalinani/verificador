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
        if (start1 != 0) {
            throw new IllegalArgumentException("ByteRange must start at 0, got: " + start1);
        }
        if (start2 < start1 + len1) {
            throw new IllegalArgumentException(
                    "ByteRange ranges must not overlap: first range ends at " + (start1 + len1)
                            + ", second range starts at " + start2);
        }
        if (start2 + len2 > fileLength) {
            throw new IllegalArgumentException(
                    "ByteRange must not exceed the file length: covers up to " + (start2 + len2)
                            + ", file length is " + fileLength);
        }
    }

    public static ByteRangeCoverage of(long start1, long len1, long start2, long len2, long fileLength) {
        return new ByteRangeCoverage(List.of(start1, len1, start2, len2), fileLength);
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
