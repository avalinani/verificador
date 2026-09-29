package com.coam.pdfvalidator.api.dto;

/**
 * One page's structural properties.
 *
 * @param rotation      the effective, normalized rotation ({@code "DEG_0"},
 *                      {@code "DEG_90"}, {@code "DEG_180"} or {@code
 *                      "DEG_270"}) used to compute {@code orientation}
 * @param rawRotation   the raw {@code /Rotate} value found in the PDF,
 *                      before normalization; see {@code rotationValid}
 * @param rotationValid whether {@code rawRotation} is trustworthy (an
 *                      actual integral multiple of 90); when {@code false},
 *                      {@code rotation} was defaulted to {@code "DEG_0"}
 *                      rather than aborting the analysis
 * @param orientation   {@code "PORTRAIT"}, {@code "LANDSCAPE"} or {@code
 *                      "SQUARE"}, computed after rotation is applied
 */
public record PageInfoDto(
        int number,
        int rawRotation,
        boolean rotationValid,
        String rotation,
        BoxDto mediaBox,
        BoxDto cropBox,
        String orientation) {
}
