package com.coam.pdfvalidator.domain.model;

/**
 * A page's normalized {@code /Rotate} value. Per the PDF specification,
 * {@code /Rotate} must be a multiple of 90 (positive or negative, of any
 * magnitude); {@link #fromDegrees(int)} normalizes it into one of the four
 * canonical values and rejects anything that is not a multiple of 90 as an
 * invalid, non-conformant document.
 */
public enum Rotation {
    DEG_0(0),
    DEG_90(90),
    DEG_180(180),
    DEG_270(270);

    private final int degrees;

    Rotation(int degrees) {
        this.degrees = degrees;
    }

    public int degrees() {
        return degrees;
    }

    /**
     * Normalizes a raw {@code /Rotate} value (possibly negative or larger
     * than 360) into one of the four canonical rotations.
     *
     * @throws IllegalArgumentException if {@code rawDegrees} is not a
     *                                  multiple of 90
     */
    public static Rotation fromDegrees(int rawDegrees) {
        if (rawDegrees % 90 != 0) {
            throw new IllegalArgumentException(
                    "PDF /Rotate must be a multiple of 90 degrees, got: " + rawDegrees);
        }
        int normalized = ((rawDegrees % 360) + 360) % 360;
        return switch (normalized) {
            case 0 -> DEG_0;
            case 90 -> DEG_90;
            case 180 -> DEG_180;
            case 270 -> DEG_270;
            default -> throw new IllegalStateException("unreachable: normalized=" + normalized);
        };
    }
}
