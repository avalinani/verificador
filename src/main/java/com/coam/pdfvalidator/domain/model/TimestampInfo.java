package com.coam.pdfvalidator.domain.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * An RFC 3161 timestamp attached to a signature (the {@code
 * id-aa-signatureTimeStampToken} unsigned CMS attribute), or its absence
 * (use {@link #absent()} rather than constructing a partially-null
 * instance).
 *
 * <p>{@code genTime} is the time the TSA claims to have issued the
 * timestamp. It is only evidence of <em>when</em> the signature existed
 * once {@link #trusted()} holds: a token whose TSA certificate merely
 * verifies against itself proves nothing, since anybody can mint a TSA and
 * write any {@code genTime}. Trust is decided by the application layer (it
 * needs the trust anchors, through the chain-validator port) and recorded
 * with {@link #withTrust}; the Bouncy Castle adapter only reports the
 * cryptographic facts it can check on the token alone and always produces
 * {@code trusted == false}.
 *
 * @param genTime            the time the TSA claims to have issued the
 *                            timestamp, or {@code null} when absent or the
 *                            token could not be parsed at all
 * @param tsaName             the TSA's certificate subject name, or {@code ""}
 *                            when unknown (absent, or a malformed token)
 * @param imprintValid        whether the token's message imprint matches the
 *                            hash (with the token's own imprint algorithm) of
 *                            the signature value it timestamps
 * @param signatureValid      whether the TSA's own CMS signature over the
 *                            token verifies against its embedded TSA
 *                            certificate
 * @param tsaCertificate      the TSA's certificate, or {@code null} when
 *                            unavailable
 * @param note                a diagnostic note for an anomaly that does not by
 *                            itself make the surrounding signature's integrity
 *                            invalid (e.g. a malformed token, a TSA
 *                            certificate missing the timeStamping extended
 *                            key usage, or a TSA that is not trusted), or
 *                            {@code null} when there is none
 * @param tsaChain            the TSA certificate followed by the issuers found
 *                            in the token (TSA first), only the certificates
 *                            linked by issuer/subject; empty when the
 *                            certificate is unavailable. Validated by the
 *                            application layer against the trust anchors
 * @param tsaTimeStampingEku  whether the TSA certificate carries the
 *                            {@code id-kp-timeStamping} extended key usage
 *                            (RFC 3161 section 2.3)
 * @param trusted             whether this timestamp may be used as the
 *                            validation time: imprint and TSA signature
 *                            valid, timeStamping EKU present, TSA chain
 *                            trusted at {@code genTime}, and {@code genTime}
 *                            not in the future
 */
public record TimestampInfo(
        Instant genTime,
        String tsaName,
        boolean imprintValid,
        boolean signatureValid,
        CertificateInfo tsaCertificate,
        String note,
        List<CertificateInfo> tsaChain,
        boolean tsaTimeStampingEku,
        boolean trusted) {

    private static final TimestampInfo ABSENT =
            new TimestampInfo(null, "", false, false, null, null, List.of(), false, false);

    public TimestampInfo {
        Objects.requireNonNull(tsaName, "tsaName");
        Objects.requireNonNull(tsaChain, "tsaChain");
        tsaChain = List.copyOf(tsaChain);
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

    /**
     * Returns a copy carrying the trust decision; {@code additionalNote}
     * (nullable) is appended to the existing note, joined by {@code "; "}.
     */
    public TimestampInfo withTrust(boolean newTrusted, String additionalNote) {
        String combined = additionalNote == null ? note : (note == null ? additionalNote : note + "; " + additionalNote);
        return new TimestampInfo(
                genTime, tsaName, imprintValid, signatureValid, tsaCertificate, combined,
                tsaChain, tsaTimeStampingEku, newTrusted);
    }
}
