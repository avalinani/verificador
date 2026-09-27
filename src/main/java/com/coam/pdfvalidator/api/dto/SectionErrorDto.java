package com.coam.pdfvalidator.api.dto;

/**
 * Records that an analysis section failed unexpectedly, so its result (e.g.
 * an empty {@code signatures} list) is never silently indistinguishable from
 * a legitimately empty one.
 *
 * @param section {@code "PDFA"} or {@code "SIGNATURES"}
 */
public record SectionErrorDto(String section, String message) {
}
