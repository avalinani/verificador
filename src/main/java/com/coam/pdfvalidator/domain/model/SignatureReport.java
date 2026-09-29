package com.coam.pdfvalidator.domain.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Full analysis result for one PDF signature. {@code chainStatus} and
 * {@code revocation} start out as {@link ChainStatus#NOT_CHECKED} /
 * {@link RevocationStatus#notChecked()} placeholders when a
 * {@code SignatureVerifier} first extracts the signature, and are later
 * replaced by the use case via {@link #withChainAndRevocation} once it has
 * validated the chain and (optionally) checked revocation.
 *
 * @param claimedSigningTime the signing time claimed inside the signature
 *                           (CMS signing-time attribute), or {@code null}
 *                           when absent — see {@link #claimedSigningTimeOptional()}
 * @param anomaly            a diagnostic note for a problem that does not
 *                            by itself invalidate this signature's
 *                            integrity (e.g. the CMS verified but part of
 *                            the certificate chain could not be mapped to
 *                            {@link CertificateInfo}, leaving it empty or
 *                            partial), or {@code null} when there is none
 *                            — see {@link #anomalyOptional()}
 * @param verdict             the overall per-signature admissibility verdict
 *                            (T11), computed by {@code
 *                            com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy}
 *                            once integrity/chain/revocation are all known.
 *                            Starts out at the safe {@link
 *                            SignatureVerdict#NOT_ADMITTED} placeholder (see
 *                            the 10-arg constructor below) until that final
 *                            pass runs, the same placeholder-then-enrich
 *                            convention already used for {@code chainStatus}/
 *                            {@code revocation}
 * @param verdictReasons      stable, non-sensitive reason codes explaining
 *                            {@code verdict} (e.g. {@code "CHAIN_EXPIRED"},
 *                            {@code "REVOCATION_UNKNOWN"}), translated to
 *                            user-facing text by the frontend, never empty
 *                            prose here
 */
public record SignatureReport(
        String fieldName,
        String subFilter,
        ByteRangeCoverage coverage,
        IntegrityStatus integrity,
        Instant claimedSigningTime,
        TimestampInfo timestamp,
        List<CertificateInfo> chain,
        ChainStatus chainStatus,
        RevocationStatus revocation,
        String anomaly,
        SignatureVerdict verdict,
        List<String> verdictReasons) {

    public SignatureReport {
        Objects.requireNonNull(fieldName, "fieldName");
        Objects.requireNonNull(subFilter, "subFilter");
        Objects.requireNonNull(coverage, "coverage");
        Objects.requireNonNull(integrity, "integrity");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(chain, "chain");
        Objects.requireNonNull(chainStatus, "chainStatus");
        Objects.requireNonNull(revocation, "revocation");
        Objects.requireNonNull(verdict, "verdict");
        Objects.requireNonNull(verdictReasons, "verdictReasons");
        chain = List.copyOf(chain);
        verdictReasons = List.copyOf(verdictReasons);
    }

    /**
     * Convenience constructor matching this record's original (pre-T11)
     * shape, used by every {@code SignatureVerifier} adapter and every
     * pre-T11 test fixture: defaults {@code verdict} to the safe {@link
     * SignatureVerdict#NOT_ADMITTED} placeholder with no reasons, exactly
     * mirroring how {@code chainStatus}/{@code revocation} already start at
     * their own {@code NOT_CHECKED} placeholders before the use case
     * enriches them. Superseded by {@link #withVerdict} once the final
     * verdict pass (over every signature in the report, since it needs to
     * see all of them together -- see {@code SignatureVerdictPolicy}) runs.
     */
    public SignatureReport(
            String fieldName,
            String subFilter,
            ByteRangeCoverage coverage,
            IntegrityStatus integrity,
            Instant claimedSigningTime,
            TimestampInfo timestamp,
            List<CertificateInfo> chain,
            ChainStatus chainStatus,
            RevocationStatus revocation,
            String anomaly) {
        this(fieldName, subFilter, coverage, integrity, claimedSigningTime, timestamp, chain,
                chainStatus, revocation, anomaly, SignatureVerdict.NOT_ADMITTED, List.of());
    }

    public Optional<Instant> claimedSigningTimeOptional() {
        return Optional.ofNullable(claimedSigningTime);
    }

    public Optional<String> anomalyOptional() {
        return Optional.ofNullable(anomaly);
    }

    /** Returns a copy of this report with the chain/revocation status enriched by the use case. */
    public SignatureReport withChainAndRevocation(ChainStatus newChainStatus, RevocationStatus newRevocation) {
        return new SignatureReport(
                fieldName, subFilter, coverage, integrity, claimedSigningTime, timestamp, chain,
                newChainStatus, newRevocation, anomaly, verdict, verdictReasons);
    }

    /** Returns a copy of this report with its final verdict (T11), computed by {@code SignatureVerdictPolicy}. */
    public SignatureReport withVerdict(SignatureVerdict newVerdict, List<String> newVerdictReasons) {
        return new SignatureReport(
                fieldName, subFilter, coverage, integrity, claimedSigningTime, timestamp, chain,
                chainStatus, revocation, anomaly, newVerdict, newVerdictReasons);
    }
}
