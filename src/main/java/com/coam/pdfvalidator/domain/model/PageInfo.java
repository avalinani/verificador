package com.coam.pdfvalidator.domain.model;

import java.util.Objects;

/**
 * One page's structural properties: 1-based number, rotation, and boxes.
 *
 * @param rawRotation the raw {@code /Rotate} value as found in the PDF,
 *                    before normalization; a hostile or malformed document
 *                    can carry any integer here, not just a multiple of 90
 * @param rotation    the effective, normalized rotation used to compute
 *                    {@code orientation}; when {@code rawRotation} is not a
 *                    multiple of 90 this is defaulted to {@link Rotation#DEG_0}
 *                    rather than aborting the analysis (see {@link #rotationValid()})
 */
public record PageInfo(int number, int rawRotation, Rotation rotation, Box mediaBox, Box cropBox, Orientation orientation) {

    public PageInfo {
        if (number < 1) {
            throw new IllegalArgumentException("page number must be >= 1, got: " + number);
        }
        Objects.requireNonNull(rotation, "rotation");
        Objects.requireNonNull(mediaBox, "mediaBox");
        Objects.requireNonNull(cropBox, "cropBox");
        Objects.requireNonNull(orientation, "orientation");
    }

    /**
     * Whether {@code rawRotation} is a valid PDF rotation (a multiple of
     * 90). When {@code false}, {@code rotation} was defaulted to
     * {@link Rotation#DEG_0} for orientation purposes, and the document
     * carries a structural anomaly worth flagging to the caller without
     * aborting the whole analysis.
     */
    public boolean rotationValid() {
        return Rotation.tryFromDegrees(rawRotation).isPresent();
    }
}
