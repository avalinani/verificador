package com.coam.pdfvalidator.domain.model;

import java.time.Instant;
import java.util.Arrays;
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

    /**
     * Compares {@code encoded} by content ({@link Arrays#equals(byte[], byte[])})
     * rather than by array identity, which the record-generated {@code equals}
     * would otherwise use.
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CertificateInfo that)) {
            return false;
        }
        return Objects.equals(subject, that.subject)
                && Objects.equals(issuer, that.issuer)
                && Objects.equals(serialNumberHex, that.serialNumberHex)
                && Objects.equals(notBefore, that.notBefore)
                && Objects.equals(notAfter, that.notAfter)
                && Objects.equals(signatureAlgorithm, that.signatureAlgorithm)
                && Objects.equals(ocspUrls, that.ocspUrls)
                && Objects.equals(crlUrls, that.crlUrls)
                && Arrays.equals(encoded, that.encoded);
    }

    /** Consistent with {@link #equals(Object)}: hashes {@code encoded} by content. */
    @Override
    public int hashCode() {
        int result = Objects.hash(
                subject, issuer, serialNumberHex, notBefore, notAfter, signatureAlgorithm, ocspUrls, crlUrls);
        return 31 * result + Arrays.hashCode(encoded);
    }

    /** Reports the encoded certificate's length instead of dumping its bytes. */
    @Override
    public String toString() {
        return ("CertificateInfo[subject=%s, issuer=%s, serialNumberHex=%s, notBefore=%s, notAfter=%s, "
                + "signatureAlgorithm=%s, ocspUrls=%s, crlUrls=%s, encoded=%d bytes]")
                        .formatted(subject, issuer, serialNumberHex, notBefore, notAfter, signatureAlgorithm,
                                ocspUrls, crlUrls, encoded.length);
    }
}
