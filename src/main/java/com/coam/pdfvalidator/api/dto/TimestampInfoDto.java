package com.coam.pdfvalidator.api.dto;

import java.time.Instant;

/**
 * An RFC 3161 timestamp attached to a signature, or its absence ({@code
 * present=false}, every other field at its default/empty value).
 *
 * @param genTime        the time the TSA claims to have issued the
 *                       timestamp, or {@code null} when absent or
 *                       unparseable
 * @param imprintValid   whether the token's message imprint matches the
 *                       signature value it timestamps
 * @param signatureValid whether the TSA's own signature over the token
 *                       verifies against its embedded certificate
 * @param note           a diagnostic note for an anomaly that does not by
 *                       itself invalidate the surrounding signature, or
 *                       {@code null}
 */
public record TimestampInfoDto(
        Instant genTime,
        String tsaName,
        boolean present,
        boolean imprintValid,
        boolean signatureValid,
        CertificateInfoDto tsaCertificate,
        String note) {
}
