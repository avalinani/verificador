package com.coam.pdfvalidator.domain.model;

/** A page's visual orientation, computed after rotation is applied. */
public enum Orientation {
    PORTRAIT,
    LANDSCAPE,
    SQUARE;

    /**
     * Computes the orientation of {@code effectiveBox} as actually rendered,
     * i.e. after {@code rotation} is applied: a 90 or 270 degree rotation
     * swaps width and height before comparing them.
     */
    public static Orientation of(Box effectiveBox, Rotation rotation) {
        boolean swapped = rotation == Rotation.DEG_90 || rotation == Rotation.DEG_270;
        float renderedWidth = swapped ? effectiveBox.height() : effectiveBox.width();
        float renderedHeight = swapped ? effectiveBox.width() : effectiveBox.height();

        if (renderedWidth == renderedHeight) {
            return SQUARE;
        }
        return renderedWidth > renderedHeight ? LANDSCAPE : PORTRAIT;
    }
}
