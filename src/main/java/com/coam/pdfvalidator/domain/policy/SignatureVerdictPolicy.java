package com.coam.pdfvalidator.domain.policy;

import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.OverallVerdict;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.SignatureVerdict;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure domain policy (T11, following the user's decisions of 2026-09-28)
 * computing the overall admissibility {@link SignatureVerdict} for a fully
 * enriched {@link SignatureReport} (integrity, chain trust and revocation
 * already known), plus the document-level {@link OverallVerdict}. Never
 * throws for any input it is given; every branch is total over its enum.
 *
 * <h2>Decision table</h2>
 * Evaluated top to bottom; the first matching row decides the verdict.
 * <table border="1">
 * <caption>Per-signature verdict</caption>
 * <tr><th>Condition</th><th>Verdict</th><th>Reason code</th></tr>
 * <tr><td>{@code integrity == INVALID_SIGNATURE}</td><td>INVALID</td><td>{@code SIGNATURE_INVALID}</td></tr>
 * <tr><td>{@code integrity == UNSUPPORTED}</td><td>NOT_ADMITTED</td><td>{@code SIGNATURE_FORMAT_UNSUPPORTED}</td></tr>
 * <tr><td>{@code integrity == MODIFIED_AFTER_SIGNING}, no later signature at
 *     all exists in the document</td>
 *     <td>INVALID</td><td>{@code MODIFIED_AFTER_LAST_SIGNATURE}</td></tr>
 * <tr><td>{@code integrity == MODIFIED_AFTER_SIGNING}, at least one later
 *     signature exists but not <em>every</em> later signature is itself
 *     admitted (a full {@code VALID} verdict -- see the SECURITY note
 *     below)</td>
 *     <td>INVALID</td><td>{@code MODIFIED_AFTER_SIGNING_BY_UNADMITTED_PARTY}</td></tr>
 * <tr><td>{@code integrity == MODIFIED_AFTER_SIGNING}, at least one later
 *     signature exists and <em>every</em> later signature is itself
 *     admitted (expected PDF multi-signature workflow: this signature's own
 *     revision was itself untouched, only a subsequent, admitted signature
 *     was appended)</td>
 *     <td>falls through to chain/revocation below, with an informational
 *     {@code COVERED_BY_LATER_SIGNATURE} reason added</td><td>--</td></tr>
 * <tr><td>no trusted timestamp (added before any row below)</td><td>--</td>
 *     <td>{@code VALIDATED_AT_CURRENT_TIME} (informational: the chain was
 *     validated at the analysis time, not at a timestamp genTime)</td></tr>
 * <tr><td>{@code chainStatus != TRUSTED}</td><td>NOT_ADMITTED</td>
 *     <td>{@code CHAIN_UNTRUSTED_ROOT} / {@code CHAIN_INCOMPLETE} /
 *     {@code CHAIN_EXPIRED} / {@code CHAIN_NOT_CHECKED}</td></tr>
 * <tr><td>chain trusted, revocation not requested for this analysis</td>
 *     <td>VALID</td><td>{@code REVOCATION_NOT_REQUESTED} (informational --
 *     the UI must say "revocacion no comprobada", not claim it was checked)</td></tr>
 * <tr><td>chain trusted, revocation requested, {@code GOOD}</td><td>VALID</td><td>--</td></tr>
 * <tr><td>chain trusted, revocation requested, {@code REVOKED}</td>
 *     <td>INVALID</td><td>{@code REVOCATION_REVOKED}</td></tr>
 * <tr><td>chain trusted, revocation requested, {@code UNKNOWN}</td>
 *     <td>NOT_ADMITTED</td><td>{@code REVOCATION_UNKNOWN}</td></tr>
 * <tr><td>chain trusted, revocation requested, still {@code NOT_CHECKED}
 *     (e.g. T10b's empty-validated-path edge case)</td>
 *     <td>NOT_ADMITTED</td><td>{@code REVOCATION_UNAVAILABLE}</td></tr>
 * </table>
 *
 * <h2>Decisions worth documenting explicitly</h2>
 * <ul>
 *   <li><b>{@code UNSUPPORTED} is {@code NOT_ADMITTED}, not {@code
 *       INVALID}</b>: an unrecognized/legacy {@code /SubFilter} means this
 *       service simply could not verify the signature one way or the
 *       other -- it is not proof the signature is bad, so treating it the
 *       same as a cryptographically broken signature would overstate what
 *       is actually known.</li>
 *   <li><b>{@code REVOKED} is always {@code INVALID}</b>, per the user's
 *       explicit decision. Caveat, also surfaced in the README: this
 *       project's OCSP/CRL clients report the responder's/CRL's
 *       <em>current</em> revocation status, not a point-in-time check as of
 *       the claimed signing time -- a certificate revoked after it validly
 *       signed a document will still be reported {@code REVOKED} here.</li>
 *   <li><b>Multi-signature coverage (SECURITY, T11c)</b>: an earlier {@code
 *       MODIFIED_AFTER_SIGNING} signature is only exempted from the
 *       modification penalty when <em>every</em> later signature in the
 *       document is itself admitted -- a full {@code VALID} verdict (trusted
 *       chain, not revoked), not merely {@code INTACT}. Before this fix, any
 *       later {@code INTACT} signature covering the whole file was enough,
 *       regardless of its own trust: an attacker could modify a
 *       trusted-signed document and re-sign it with a self-made,
 *       untrusted-root certificate, and the original (untouched) signature
 *       would still be reported {@code VALID}, because <em>a</em> signature
 *       (the attacker's) covered the file end-to-end. Requiring every later
 *       signature to be admitted closes this: only an admitted signer --
 *       one this service actually trusts -- can vouch for the appended
 *       revision. This is still a structural check only -- {@link
 *       #laterSignatureCoverage} requires every later signature's own
 *       already-computed {@link SignatureVerdict verdict} to be {@code
 *       VALID} (trusted chain, not revoked, and either {@code INTACT} itself
 *       or, recursively, covered by a further later {@code VALID} signature);
 *       it never inspects a later signature's {@code ByteRangeCoverage}
 *       directly, only its final verdict -- it does not diff the bytes an
 *       incremental update actually appended, so it cannot distinguish "a
 *       legitimate second signature" from "an admitted party's incremental
 *       update that happens to be followed by one". See {@link
 *       #documentModifiedAfterLastSignature} and README §2.13.</li>
 * </ul>
 */
public final class SignatureVerdictPolicy {

    public static final String REASON_SIGNATURE_INVALID = "SIGNATURE_INVALID";
    public static final String REASON_SIGNATURE_FORMAT_UNSUPPORTED = "SIGNATURE_FORMAT_UNSUPPORTED";
    public static final String REASON_MODIFIED_AFTER_LAST_SIGNATURE = "MODIFIED_AFTER_LAST_SIGNATURE";
    public static final String REASON_MODIFIED_AFTER_SIGNING_BY_UNADMITTED_PARTY =
            "MODIFIED_AFTER_SIGNING_BY_UNADMITTED_PARTY";
    public static final String REASON_COVERED_BY_LATER_SIGNATURE = "COVERED_BY_LATER_SIGNATURE";
    public static final String REASON_VALIDATED_AT_CURRENT_TIME = "VALIDATED_AT_CURRENT_TIME";
    public static final String REASON_CHAIN_UNTRUSTED_ROOT = "CHAIN_UNTRUSTED_ROOT";
    public static final String REASON_CHAIN_INCOMPLETE = "CHAIN_INCOMPLETE";
    public static final String REASON_CHAIN_EXPIRED = "CHAIN_EXPIRED";
    public static final String REASON_CHAIN_NOT_CHECKED = "CHAIN_NOT_CHECKED";
    public static final String REASON_REVOCATION_NOT_REQUESTED = "REVOCATION_NOT_REQUESTED";
    public static final String REASON_REVOCATION_REVOKED = "REVOCATION_REVOKED";
    public static final String REASON_REVOCATION_UNKNOWN = "REVOCATION_UNKNOWN";
    public static final String REASON_REVOCATION_UNAVAILABLE = "REVOCATION_UNAVAILABLE";

    private SignatureVerdictPolicy() {
    }

    /**
     * Evaluates every signature in {@code signatures} together (multi-
     * signature coverage needs to see all of them at once) and returns a new
     * list with each one's {@link SignatureReport#verdict()} populated via
     * {@link SignatureReport#withVerdict}.
     *
     * @param revocationRequested {@link com.coam.pdfvalidator.application.AnalysisOptions#checkRevocation()}
     *                             for this analysis -- the application layer
     *                             is the only place that still knows this by
     *                             the time verdicts are computed, since a
     *                             {@link com.coam.pdfvalidator.domain.model.RevocationStatus}
     *                             of {@code NOT_CHECKED} alone cannot
     *                             distinguish "not requested" from every
     *                             other reason revocation ended up
     *                             unresolved
     */
    public static List<SignatureReport> evaluateAll(List<SignatureReport> signatures, boolean revocationRequested) {
        Objects.requireNonNull(signatures, "signatures");
        int total = signatures.size();
        SignatureReport[] evaluated = new SignatureReport[total];
        // Evaluated from the LAST signature backwards: whether an earlier
        // signature is "covered" depends on whether every later signature is
        // itself admitted (VALID) -- see LaterSignatureCoverage and the class
        // Javadoc's SECURITY note -- so every later signature must already
        // be evaluated before an earlier one can be.
        for (int index = total - 1; index >= 0; index--) {
            LaterSignatureCoverage coverage = laterSignatureCoverage(evaluated, index, total);
            evaluated[index] = evaluate(signatures.get(index), revocationRequested, coverage);
        }
        return List.of(evaluated);
    }

    private static LaterSignatureCoverage laterSignatureCoverage(
            SignatureReport[] evaluatedFromTheEnd, int index, int total) {
        if (index == total - 1) {
            return LaterSignatureCoverage.NO_LATER_SIGNATURE;
        }
        for (int later = index + 1; later < total; later++) {
            if (evaluatedFromTheEnd[later].verdict() != SignatureVerdict.VALID) {
                return LaterSignatureCoverage.UNADMITTED;
            }
        }
        return LaterSignatureCoverage.ADMITTED;
    }

    /**
     * Whether an earlier {@code MODIFIED_AFTER_SIGNING} signature is exempt
     * from the modification penalty (T11c SECURITY fix -- see the class
     * Javadoc's "Multi-signature coverage" note).
     */
    public enum LaterSignatureCoverage {
        /** No later signature exists in the document at all. */
        NO_LATER_SIGNATURE,
        /** At least one later signature exists, and every one of them is itself admitted ({@code VALID}). */
        ADMITTED,
        /** At least one later signature exists, but at least one of them is not admitted. */
        UNADMITTED
    }

    /** Evaluates one already-enriched signature; see the class Javadoc's decision table. */
    public static SignatureReport evaluate(
            SignatureReport signature, boolean revocationRequested, LaterSignatureCoverage laterSignatureCoverage) {
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(laterSignatureCoverage, "laterSignatureCoverage");
        List<String> reasons = new ArrayList<>();

        if (signature.integrity() == IntegrityStatus.INVALID_SIGNATURE) {
            reasons.add(REASON_SIGNATURE_INVALID);
            return signature.withVerdict(SignatureVerdict.INVALID, reasons);
        }
        if (signature.integrity() == IntegrityStatus.UNSUPPORTED) {
            reasons.add(REASON_SIGNATURE_FORMAT_UNSUPPORTED);
            return signature.withVerdict(SignatureVerdict.NOT_ADMITTED, reasons);
        }
        if (signature.integrity() == IntegrityStatus.MODIFIED_AFTER_SIGNING) {
            switch (laterSignatureCoverage) {
                case NO_LATER_SIGNATURE -> {
                    reasons.add(REASON_MODIFIED_AFTER_LAST_SIGNATURE);
                    return signature.withVerdict(SignatureVerdict.INVALID, reasons);
                }
                case UNADMITTED -> {
                    reasons.add(REASON_MODIFIED_AFTER_SIGNING_BY_UNADMITTED_PARTY);
                    return signature.withVerdict(SignatureVerdict.INVALID, reasons);
                }
                case ADMITTED -> {
                    reasons.add(REASON_COVERED_BY_LATER_SIGNATURE);
                    // Falls through: this signature's own (untouched)
                    // revision is still evaluated on its own chain/
                    // revocation merits below.
                }
            }
        }

        // The chain below was validated at the current time unless a TRUSTED
        // timestamp fixed an earlier instant (T19): say so, informationally.
        if (!signature.timestamp().trusted()) {
            reasons.add(REASON_VALIDATED_AT_CURRENT_TIME);
        }

        SignatureVerdict chainVerdict = switch (signature.chainStatus()) {
            case TRUSTED -> null;
            case UNTRUSTED_ROOT -> {
                reasons.add(REASON_CHAIN_UNTRUSTED_ROOT);
                yield SignatureVerdict.NOT_ADMITTED;
            }
            case INCOMPLETE_CHAIN -> {
                reasons.add(REASON_CHAIN_INCOMPLETE);
                yield SignatureVerdict.NOT_ADMITTED;
            }
            case EXPIRED -> {
                reasons.add(REASON_CHAIN_EXPIRED);
                yield SignatureVerdict.NOT_ADMITTED;
            }
            case NOT_CHECKED -> {
                reasons.add(REASON_CHAIN_NOT_CHECKED);
                yield SignatureVerdict.NOT_ADMITTED;
            }
        };
        if (chainVerdict != null) {
            return signature.withVerdict(chainVerdict, reasons);
        }

        // chainStatus == TRUSTED from here on.
        if (!revocationRequested) {
            reasons.add(REASON_REVOCATION_NOT_REQUESTED);
            return signature.withVerdict(SignatureVerdict.VALID, reasons);
        }

        RevocationState state = signature.revocation().state();
        return switch (state) {
            case GOOD -> signature.withVerdict(SignatureVerdict.VALID, reasons);
            case REVOKED -> {
                reasons.add(REASON_REVOCATION_REVOKED);
                yield signature.withVerdict(SignatureVerdict.INVALID, reasons);
            }
            case UNKNOWN -> {
                reasons.add(REASON_REVOCATION_UNKNOWN);
                yield signature.withVerdict(SignatureVerdict.NOT_ADMITTED, reasons);
            }
            case NOT_CHECKED -> {
                reasons.add(REASON_REVOCATION_UNAVAILABLE);
                yield signature.withVerdict(SignatureVerdict.NOT_ADMITTED, reasons);
            }
        };
    }

    /**
     * The worst {@link SignatureVerdict} among {@code signatures} ({@code
     * INVALID} > {@code NOT_ADMITTED} > {@code VALID}), or {@link
     * OverallVerdict#NO_SIGNATURES} when the document has none at all.
     */
    public static OverallVerdict overallVerdict(List<SignatureReport> signatures) {
        Objects.requireNonNull(signatures, "signatures");
        if (signatures.isEmpty()) {
            return OverallVerdict.NO_SIGNATURES;
        }
        if (signatures.stream().anyMatch(s -> s.verdict() == SignatureVerdict.INVALID)) {
            return OverallVerdict.INVALID;
        }
        if (signatures.stream().anyMatch(s -> s.verdict() == SignatureVerdict.NOT_ADMITTED)) {
            return OverallVerdict.NOT_ADMITTED;
        }
        return OverallVerdict.VALID;
    }

    /**
     * True when the document has at least one signature and <em>none</em> of
     * them cover the file all the way to its true end -- i.e. bytes were
     * appended after every signature's own signed revision, with nothing
     * that itself validly signs that final state. See the class Javadoc's
     * "Multi-signature coverage" caveat for what this does and does not
     * prove.
     */
    public static boolean documentModifiedAfterLastSignature(List<SignatureReport> signatures) {
        Objects.requireNonNull(signatures, "signatures");
        if (signatures.isEmpty()) {
            return false;
        }
        return signatures.stream().noneMatch(s -> s.coverage().coversWholeDocument());
    }
}
