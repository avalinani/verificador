package com.coam.pdfvalidator.api.dto;

/** A rectangular PDF box (media box, crop box, ...) in default user space units. */
public record BoxDto(float llx, float lly, float urx, float ury, float width, float height) {
}
