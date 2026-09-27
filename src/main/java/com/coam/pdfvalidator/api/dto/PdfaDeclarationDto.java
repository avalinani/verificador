package com.coam.pdfvalidator.api.dto;

/**
 * The PDF/A conformance the document itself declares via its XMP {@code
 * pdfaid} metadata (not necessarily what it actually, formally conforms to
 * -- see {@link PdfaReportDto#status()}).
 *
 * @param declared whether the document declares any PDF/A part at all;
 *                 {@code part}/{@code conformance} are {@code null} when
 *                 {@code false}
 */
public record PdfaDeclarationDto(Integer part, String conformance, boolean declared) {
}
