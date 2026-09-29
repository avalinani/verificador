package com.coam.pdfvalidator.api.dto;

import java.time.Instant;
import java.util.List;

/**
 * Full analysis result for one PDF signature field.
 *
 * @param integrity   {@code "INTACT"}, {@code "MODIFIED_AFTER_SIGNING"},
 *                    {@code "INVALID_SIGNATURE"} or {@code "UNSUPPORTED"}
 * @param chainStatus {@code "TRUSTED"}, {@code "UNTRUSTED_ROOT"}, {@code
 *                    "INCOMPLETE_CHAIN"}, {@code "EXPIRED"} or {@code
 *                    "NOT_CHECKED"}
 * @param anomaly     a diagnostic note for a problem that does not by
 *                    itself invalidate this signature's integrity (e.g. a
 *                    certificate in its chain could not be mapped), or
 *                    {@code null}
 */
public record SignatureReportDto(
        String fieldName,
        String subFilter,
        ByteRangeCoverageDto coverage,
        String integrity,
        Instant claimedSigningTime,
        TimestampInfoDto timestamp,
        List<CertificateInfoDto> chain,
        String chainStatus,
        RevocationStatusDto revocation,
        String anomaly) {
}
