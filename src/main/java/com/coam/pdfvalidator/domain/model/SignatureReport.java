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
        RevocationStatus revocation) {

    public SignatureReport {
        Objects.requireNonNull(fieldName, "fieldName");
        Objects.requireNonNull(subFilter, "subFilter");
        Objects.requireNonNull(coverage, "coverage");
        Objects.requireNonNull(integrity, "integrity");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(chain, "chain");
        Objects.requireNonNull(chainStatus, "chainStatus");
        Objects.requireNonNull(revocation, "revocation");
        chain = List.copyOf(chain);
    }

    public Optional<Instant> claimedSigningTimeOptional() {
        return Optional.ofNullable(claimedSigningTime);
    }

    /** Returns a copy of this report with the chain/revocation status enriched by the use case. */
    public SignatureReport withChainAndRevocation(ChainStatus newChainStatus, RevocationStatus newRevocation) {
        return new SignatureReport(
                fieldName, subFilter, coverage, integrity, claimedSigningTime, timestamp, chain,
                newChainStatus, newRevocation);
    }
}
