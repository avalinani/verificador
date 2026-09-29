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
 * @param anomaly        a diagnostic note for a problem that does not by
 *                       itself invalidate this signature's integrity (e.g. a
 *                       certificate in its chain could not be mapped), or
 *                       {@code null}
 * @param verdict        the overall per-signature admissibility verdict
 *                       (T11): {@code "VALID"}, {@code "NOT_ADMITTED"} or
 *                       {@code "INVALID"} -- see {@code
 *                       com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy}
 *                       for the full decision table
 * @param verdictReasons stable reason codes explaining {@code verdict} (e.g.
 *                       {@code "CHAIN_EXPIRED"}, {@code "REVOCATION_UNKNOWN"},
 *                       {@code "REVOCATION_NOT_REQUESTED"}) -- the frontend
 *                       translates these to user-facing Spanish text, never
 *                       returned as prose here
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
        String anomaly,
        String verdict,
        List<String> verdictReasons) {
}
