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
 * <tr><td>{@code integrity == MODIFIED_AFTER_SIGNING}, no later signature in
 *     the document is {@code INTACT} and covers the whole file</td>
 *     <td>INVALID</td><td>{@code MODIFIED_AFTER_LAST_SIGNATURE}</td></tr>
 * <tr><td>{@code integrity == MODIFIED_AFTER_SIGNING}, a later signature
 *     <em>is</em> {@code INTACT} and covers the whole file (expected PDF
 *     multi-signature workflow: this signature's own revision was itself
 *     untouched, only a subsequent signature was appended)</td>
 *     <td>falls through to chain/revocation below, with an informational
 *     {@code COVERED_BY_LATER_SIGNATURE} reason added</td><td>--</td></tr>
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
 *   <li><b>Multi-signature coverage</b>: this is a structural check only
 *       (does <em>any</em> signature's {@code ByteRangeCoverage} reach the
 *       true end of file, and is that signature itself {@code INTACT}) --
 *       it does not diff the bytes an incremental update actually appended,
 *       so it cannot distinguish "a legitimate second signature" from "an
 *       incremental update that happens to be followed by one". See {@link
 *       #documentModifiedAfterLastSignature}.</li>
 * </ul>
 */
public final class SignatureVerdictPolicy {

    public static final String REASON_SIGNATURE_INVALID = "SIGNATURE_INVALID";
    public static final String REASON_SIGNATURE_FORMAT_UNSUPPORTED = "SIGNATURE_FORMAT_UNSUPPORTED";
    public static final String REASON_MODIFIED_AFTER_LAST_SIGNATURE = "MODIFIED_AFTER_LAST_SIGNATURE";
    public static final String REASON_COVERED_BY_LATER_SIGNATURE = "COVERED_BY_LATER_SIGNATURE";
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
        boolean coveredByLaterIntactSignature = anySignatureIsIntact(signatures);
        List<SignatureReport> result = new ArrayList<>(signatures.size());
        for (SignatureReport signature : signatures) {
            result.add(evaluate(signature, revocationRequested, coveredByLaterIntactSignature));
        }
        return List.copyOf(result);
    }

    /** Evaluates one already-enriched signature; see the class Javadoc's decision table. */
    public static SignatureReport evaluate(
            SignatureReport signature, boolean revocationRequested, boolean anySignatureIsIntactInTheDocument) {
        Objects.requireNonNull(signature, "signature");
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
            if (!anySignatureIsIntactInTheDocument) {
                reasons.add(REASON_MODIFIED_AFTER_LAST_SIGNATURE);
                return signature.withVerdict(SignatureVerdict.INVALID, reasons);
            }
            reasons.add(REASON_COVERED_BY_LATER_SIGNATURE);
            // Falls through: this signature's own (untouched) revision is
            // still evaluated on its own chain/revocation merits below.
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

    /**
     * Whether any signature in the document is {@link IntegrityStatus#INTACT}
     * -- which, by {@code BcSignatureVerifier}'s own contract, is only ever
     * assigned when that signature's CMS verified <em>and</em> its {@code
     * ByteRangeCoverage} reaches the true end of file. Used both to decide
     * whether an earlier {@code MODIFIED_AFTER_SIGNING} signature is
     * "covered", and (indirectly, via {@code chainStatus == TRUSTED} on that
     * same signature) that the later signature's own trust was positively
     * confirmed -- an {@code INTACT} signature can still end up {@code
     * NOT_ADMITTED}/{@code INVALID} on its own chain/revocation merits, in
     * which case earlier signatures are still exempted from the
     * modification penalty (the document's <em>final</em> content is
     * genuinely covered by a signature that has not been tampered with),
     * even though that final signature is not itself admissible.
     */
    private static boolean anySignatureIsIntact(List<SignatureReport> signatures) {
        return signatures.stream().anyMatch(s -> s.integrity() == IntegrityStatus.INTACT);
    }
}
