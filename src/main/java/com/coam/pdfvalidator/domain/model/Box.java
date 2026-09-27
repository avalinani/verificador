package com.coam.pdfvalidator.domain.model;

/** A rectangular PDF box (media box, crop box, ...) in default user space units. */
public record Box(float llx, float lly, float urx, float ury) {

    public Box {
        if (urx < llx || ury < lly) {
            throw new IllegalArgumentException(
                    "Box upper-right corner must not be before the lower-left corner: "
                            + "(%s, %s) -> (%s, %s)".formatted(llx, lly, urx, ury));
        }
    }

    public float width() {
        return urx - llx;
    }

    public float height() {
        return ury - lly;
    }
}
