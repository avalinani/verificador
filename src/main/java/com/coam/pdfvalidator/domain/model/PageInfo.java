package com.coam.pdfvalidator.domain.model;

import java.util.Objects;
import java.util.Optional;

/**
 * One page's structural properties: 1-based number, rotation, and boxes.
 *
 * @param rawRotation   the raw {@code /Rotate} value as found in the PDF,
 *                      before normalization; a hostile or malformed document
 *                      can carry any integer here, not just a multiple of 90.
 *                      When the actual {@code /Rotate} entry is not a whole
 *                      number at all (e.g. a non-integral {@code COSFloat}
 *                      such as {@code 90.5}, or a non-numeric object), the
 *                      reader still reports its best-effort truncated int
 *                      here for visibility, but {@code rotationValid} is
 *                      {@code false} regardless of whether the truncated
 *                      value happens to be a multiple of 90
 * @param rotationValid whether the reader considers {@code rawRotation}
 *                      trustworthy: it must come from an actual integral
 *                      number (a {@code COSInteger}, or a {@code COSFloat}
 *                      with no fractional part) that is a multiple of 90.
 *                      Stored explicitly (rather than derived purely from
 *                      {@code rawRotation}) because the reader can detect
 *                      invalidity the truncated int alone cannot express
 * @param rotation      the effective, normalized rotation used to compute
 *                      {@code orientation}; when {@code rotationValid} is
 *                      {@code false} this is defaulted to {@link Rotation#DEG_0}
 *                      rather than aborting the analysis
 */
public record PageInfo(
        int number, int rawRotation, boolean rotationValid, Rotation rotation, Box mediaBox, Box cropBox,
        Orientation orientation) {

    public PageInfo {
        if (number < 1) {
            throw new IllegalArgumentException("page number must be >= 1, got: " + number);
        }
        Objects.requireNonNull(rotation, "rotation");
        Objects.requireNonNull(mediaBox, "mediaBox");
        Objects.requireNonNull(cropBox, "cropBox");
        Objects.requireNonNull(orientation, "orientation");
        Optional<Rotation> normalized = Rotation.tryFromDegrees(rawRotation);
        if (rotationValid) {
            if (normalized.isEmpty()) {
                throw new IllegalArgumentException(
                        "rotationValid=true but rawRotation " + rawRotation + " is not a multiple of 90");
            }
            if (rotation != normalized.get()) {
                throw new IllegalArgumentException(
                        "rotation " + rotation + " does not match the normalized value of rawRotation "
                                + rawRotation + " (" + normalized.get() + ")");
            }
        } else if (rotation != Rotation.DEG_0) {
            throw new IllegalArgumentException(
                    "rotationValid=false but rotation is not the default DEG_0 fallback: " + rotation);
        }
    }
}
