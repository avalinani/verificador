package com.coam.pdfvalidator.domain.model;

import java.util.Objects;

/** One page's structural properties: 1-based number, rotation, and boxes. */
public record PageInfo(int number, Rotation rotation, Box mediaBox, Box cropBox, Orientation orientation) {

    public PageInfo {
        if (number < 1) {
            throw new IllegalArgumentException("page number must be >= 1, got: " + number);
        }
        Objects.requireNonNull(rotation, "rotation");
        Objects.requireNonNull(mediaBox, "mediaBox");
        Objects.requireNonNull(cropBox, "cropBox");
        Objects.requireNonNull(orientation, "orientation");
    }
}
