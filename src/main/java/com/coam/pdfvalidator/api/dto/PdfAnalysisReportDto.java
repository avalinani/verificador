package com.coam.pdfvalidator.api.dto;

import java.time.Instant;
import java.util.List;

/**
 * The complete, single-pass audit result for one uploaded PDF file --
 * mirrors the domain's {@code PdfAnalysisReport} field for field, but
 * exposes only stable, documented, JSON-friendly field names and never a
 * domain or third-party library type directly (see {@code
 * PdfAnalysisReportMapper}).
 */
public record PdfAnalysisReportDto(
        String fileName,
        long sizeBytes,
        DocumentHashesDto hashes,
        DocumentStructureDto structure,
        SecurityInfoDto security,
        PdfaReportDto pdfa,
        List<SignatureReportDto> signatures,
        Instant analyzedAt,
        List<SectionErrorDto> sectionErrors) {
}
