package com.coam.pdfvalidator.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * An RFC 3161 timestamp attached to a signature (the {@code
 * id-aa-signatureTimeStampToken} unsigned CMS attribute), or its absence
 * (use {@link #absent()} rather than constructing a partially-null
 * instance).
 *
 * <p>{@code genTime} is the time the TSA claims to have issued the
 * timestamp -- a strong, independently-verifiable claim once {@link
 * #imprintValid()} and {@link #signatureValid()} both hold -- as opposed to
 * a signature's own claimed/self-declared signing time ({@code /M} or the
 * signed {@code signingTime} attribute), which the signer could set to
 * anything.
 *
 * @param genTime        the time the TSA claims to have issued the
 *                        timestamp, or {@code null} when absent or the
 *                        token could not be parsed at all
 * @param tsaName         the TSA's certificate subject name, or {@code ""}
 *                        when unknown (absent, or a malformed token)
 * @param imprintValid    whether the token's message imprint matches the
 *                        hash (with the token's own imprint algorithm) of
 *                        the signature value it timestamps
 * @param signatureValid  whether the TSA's own CMS signature over the
 *                        token verifies against its embedded TSA
 *                        certificate
 * @param tsaCertificate  the TSA's certificate, or {@code null} when
 *                        unavailable
 * @param note            a diagnostic note for an anomaly that does not by
 *                         itself make the surrounding signature's integrity
 *                         invalid (e.g. a malformed token, or a TSA
 *                         certificate missing the timeStamping extended
 *                         key usage), or {@code null} when there is none
 */
public record TimestampInfo(
        Instant genTime,
        String tsaName,
        boolean imprintValid,
        boolean signatureValid,
        CertificateInfo tsaCertificate,
        String note) {

    private static final TimestampInfo ABSENT = new TimestampInfo(null, "", false, false, null, null);

    public TimestampInfo {
        Objects.requireNonNull(tsaName, "tsaName");
    }

    public static TimestampInfo absent() {
        return ABSENT;
    }

    public boolean isPresent() {
        return genTime != null;
    }

    public Optional<CertificateInfo> tsaCertificateOptional() {
        return Optional.ofNullable(tsaCertificate);
    }

    public Optional<String> noteOptional() {
        return Optional.ofNullable(note);
    }
}
