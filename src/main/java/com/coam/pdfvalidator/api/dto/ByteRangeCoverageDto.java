package com.coam.pdfvalidator.api.dto;

import java.util.List;

/**
 * A signature's {@code /ByteRange}: the four raw values {@code [start1,
 * len1, start2, len2]} plus the derived {@code coversWholeDocument}
 * convenience flag.
 */
public record ByteRangeCoverageDto(List<Long> ranges, long fileLength, boolean coversWholeDocument) {
    public ByteRangeCoverageDto {
        ranges = List.copyOf(ranges);
    }
}
