package com.coam.pdfvalidator.domain.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * An X.509 certificate as needed for reporting and chain/revocation
 * checking. {@code encoded} carries the DER-encoded certificate bytes
 * (defensively copied both ways) so a {@code CertificateChainValidator} can
 * rebuild a real certificate object without the domain depending on any
 * X.509 library.
 */
public record CertificateInfo(
        String subject,
        String issuer,
        String serialNumberHex,
        Instant notBefore,
        Instant notAfter,
        String signatureAlgorithm,
        List<String> ocspUrls,
        List<String> crlUrls,
        byte[] encoded) {

    public CertificateInfo {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(serialNumberHex, "serialNumberHex");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        Objects.requireNonNull(ocspUrls, "ocspUrls");
        Objects.requireNonNull(crlUrls, "crlUrls");
        Objects.requireNonNull(encoded, "encoded");
        ocspUrls = List.copyOf(ocspUrls);
        crlUrls = List.copyOf(crlUrls);
        encoded = encoded.clone();
    }

    /** Defensive copy: mutating the returned array never affects this record. */
    @Override
    public byte[] encoded() {
        return encoded.clone();
    }

    public boolean isValidAt(Instant instant) {
        return !instant.isBefore(notBefore) && !instant.isAfter(notAfter);
    }
}
