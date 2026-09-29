package com.coam.pdfvalidator.api.dto;

import java.time.Instant;
import java.util.List;

/**
 * An X.509 certificate, reported without ever exposing its raw DER encoding:
 * only the fields needed to identify and reason about it, plus a SHA-256
 * fingerprint of the certificate as a stable, compact identifier a client
 * can compare or look up without needing the certificate bytes themselves.
 */
public record CertificateInfoDto(
        String subject,
        String issuer,
        String serialNumberHex,
        Instant notBefore,
        Instant notAfter,
        String signatureAlgorithm,
        List<String> ocspUrls,
        List<String> crlUrls,
        String sha256Fingerprint) {
}
