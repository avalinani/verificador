package com.coam.pdfvalidator.api.dto;

import java.time.Instant;
import java.util.List;

/**
 * The complete, single-pass audit result for one uploaded PDF file --
 * mirrors the domain's {@code PdfAnalysisReport} field for field, but
 * exposes only stable, documented, JSON-friendly field names and never a
 * domain or third-party library type directly (see {@code
 * PdfAnalysisReportMapper}).
 *
 * @param overallVerdict            the document-level summary verdict (T11):
 *                                  the worst of every signature's own {@code
 *                                  verdict}, or {@code "NO_SIGNATURES"} for
 *                                  an unsigned document
 * @param modifiedAfterLastSignature true when the document has at least one
 *                                  signature and none of them cover the file
 *                                  all the way to its true end -- see {@code
 *                                  SignatureVerdictPolicy#documentModifiedAfterLastSignature}
 *                                  for exactly what this does and does not
 *                                  prove (a structural, not content-diffing,
 *                                  check)
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
        List<SectionErrorDto> sectionErrors,
        String overallVerdict,
        boolean modifiedAfterLastSignature) {
    public PdfAnalysisReportDto {
        signatures = List.copyOf(signatures);
        sectionErrors = List.copyOf(sectionErrors);
    }
}
