package com.coam.pdfvalidator.domain.policy;

import com.coam.pdfvalidator.domain.model.ByteRangeCoverage;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.OverallVerdict;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.SignatureVerdict;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every row of {@link SignatureVerdictPolicy}'s decision table, plus the
 * multi-signature "covered by later signature" cases (T11, per the user's
 * decisions of 2026-09-28).
 */
class SignatureVerdictPolicyTest {

    // ---- single-signature decision table rows ----

    @Test
    void invalidSignatureIsAlwaysInvalidRegardlessOfChainOrRevocation() {
        SignatureReport signature = signature(IntegrityStatus.INVALID_SIGNATURE, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, true, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.INVALID);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_SIGNATURE_INVALID);
    }

    @Test
    void unsupportedSubfilterIsNotAdmittedNotInvalid() {
        SignatureReport signature = signature(IntegrityStatus.UNSUPPORTED, wholeDocumentCoverage(),
                ChainStatus.NOT_CHECKED, RevocationStatus.notChecked());

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, false, false);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_SIGNATURE_FORMAT_UNSUPPORTED);
    }

    @Test
    void modifiedAfterSigningWithNoLaterIntactSignatureIsInvalid() {
        SignatureReport signature = signature(IntegrityStatus.MODIFIED_AFTER_SIGNING, partialCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, true, false);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.INVALID);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_MODIFIED_AFTER_LAST_SIGNATURE);
    }

    @Test
    void modifiedAfterSigningCoveredByALaterIntactSignatureFallsThroughToChainAndRevocation() {
        SignatureReport signature = signature(IntegrityStatus.MODIFIED_AFTER_SIGNING, partialCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, true, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_COVERED_BY_LATER_SIGNATURE);
    }

    @Test
    void untrustedRootIsNotAdmitted() {
        assertChainStatusIsNotAdmitted(ChainStatus.UNTRUSTED_ROOT, SignatureVerdictPolicy.REASON_CHAIN_UNTRUSTED_ROOT);
    }

    @Test
    void incompleteChainIsNotAdmitted() {
        assertChainStatusIsNotAdmitted(ChainStatus.INCOMPLETE_CHAIN, SignatureVerdictPolicy.REASON_CHAIN_INCOMPLETE);
    }

    @Test
    void expiredChainIsNotAdmitted() {
        assertChainStatusIsNotAdmitted(ChainStatus.EXPIRED, SignatureVerdictPolicy.REASON_CHAIN_EXPIRED);
    }

    @Test
    void notCheckedChainIsNotAdmitted() {
        assertChainStatusIsNotAdmitted(ChainStatus.NOT_CHECKED, SignatureVerdictPolicy.REASON_CHAIN_NOT_CHECKED);
    }

    private void assertChainStatusIsNotAdmitted(ChainStatus chainStatus, String expectedReason) {
        SignatureReport signature = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                chainStatus, RevocationStatus.notChecked());

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, false, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
        assertThat(result.verdictReasons()).containsExactly(expectedReason);
    }

    @Test
    void trustedChainWithRevocationNotRequestedIsValidWithAnInformationalReason() {
        SignatureReport signature = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, RevocationStatus.notChecked());

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, false, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_REVOCATION_NOT_REQUESTED);
    }

    @Test
    void trustedChainWithGoodRevocationIsValid() {
        SignatureReport signature = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, true, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(result.verdictReasons()).isEmpty();
    }

    @Test
    void trustedChainWithRevokedCertificateIsInvalid() {
        SignatureReport signature = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.REVOKED, "OCSP", null));

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, true, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.INVALID);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_REVOCATION_REVOKED);
    }

    @Test
    void trustedChainWithUnknownRevocationIsNotAdmitted() {
        SignatureReport signature = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.UNKNOWN, null, "no OCSP/CRL URL available"));

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, true, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_REVOCATION_UNKNOWN);
    }

    /** T10b's own empty-validated-path edge case: requested, trusted chain, still NOT_CHECKED. */
    @Test
    void trustedChainWithRevocationRequestedButStillNotCheckedIsNotAdmitted() {
        SignatureReport signature = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(
                        RevocationState.NOT_CHECKED, null, "validated certification path unavailable"));

        SignatureReport result = SignatureVerdictPolicy.evaluate(signature, true, true);

        assertThat(result.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
        assertThat(result.verdictReasons()).containsExactly(SignatureVerdictPolicy.REASON_REVOCATION_UNAVAILABLE);
    }

    // ---- overallVerdict / documentModifiedAfterLastSignature ----

    @Test
    void overallVerdictIsNoSignaturesForAnUnsignedDocument() {
        assertThat(SignatureVerdictPolicy.overallVerdict(List.of())).isEqualTo(OverallVerdict.NO_SIGNATURES);
    }

    @Test
    void overallVerdictIsTheWorstOfEverySignature() {
        SignatureReport valid = withVerdict(SignatureVerdict.VALID);
        SignatureReport notAdmitted = withVerdict(SignatureVerdict.NOT_ADMITTED);
        SignatureReport invalid = withVerdict(SignatureVerdict.INVALID);

        assertThat(SignatureVerdictPolicy.overallVerdict(List.of(valid))).isEqualTo(OverallVerdict.VALID);
        assertThat(SignatureVerdictPolicy.overallVerdict(List.of(valid, notAdmitted))).isEqualTo(OverallVerdict.NOT_ADMITTED);
        assertThat(SignatureVerdictPolicy.overallVerdict(List.of(valid, notAdmitted, invalid))).isEqualTo(OverallVerdict.INVALID);
    }

    @Test
    void documentIsNotFlaggedModifiedAfterLastSignatureWhenOneSignatureCoversTheWholeFile() {
        SignatureReport intact = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, RevocationStatus.notChecked());

        assertThat(SignatureVerdictPolicy.documentModifiedAfterLastSignature(List.of(intact))).isFalse();
    }

    @Test
    void documentIsFlaggedModifiedAfterLastSignatureWhenNoSignatureReachesTheEndOfFile() {
        SignatureReport modified = signature(IntegrityStatus.MODIFIED_AFTER_SIGNING, partialCoverage(),
                ChainStatus.TRUSTED, RevocationStatus.notChecked());

        assertThat(SignatureVerdictPolicy.documentModifiedAfterLastSignature(List.of(modified))).isTrue();
    }

    @Test
    void anUnsignedDocumentIsNotFlaggedModifiedAfterLastSignature() {
        assertThat(SignatureVerdictPolicy.documentModifiedAfterLastSignature(List.of())).isFalse();
    }

    /**
     * Full multi-signature scenario (the user's example): an earlier
     * signature followed only by a later signature's own incremental update
     * must not be flagged invalid -- its own chain/revocation still decide
     * its verdict, and the document itself is not "modified after the last
     * signature" since the later signature does cover the whole file.
     */
    @Test
    void twoSignatureDocumentWhereTheSecondCoversTheWholeFileExemptsTheFirstFromTheModificationPenalty() {
        SignatureReport first = signature(IntegrityStatus.MODIFIED_AFTER_SIGNING,
                ByteRangeCoverage.of(0, 10, 20, 5, 100), ChainStatus.TRUSTED,
                new RevocationStatus(RevocationState.GOOD, "OCSP", null));
        SignatureReport second = signature(IntegrityStatus.INTACT, wholeDocumentCoverage(),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        List<SignatureReport> evaluated = SignatureVerdictPolicy.evaluateAll(List.of(first, second), true);

        assertThat(evaluated.get(0).verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(evaluated.get(0).verdictReasons()).contains(SignatureVerdictPolicy.REASON_COVERED_BY_LATER_SIGNATURE);
        assertThat(evaluated.get(1).verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(SignatureVerdictPolicy.overallVerdict(evaluated)).isEqualTo(OverallVerdict.VALID);
        assertThat(SignatureVerdictPolicy.documentModifiedAfterLastSignature(evaluated)).isFalse();
    }

    // ---- fixtures ----

    private static SignatureReport withVerdict(SignatureVerdict verdict) {
        return signature(IntegrityStatus.INTACT, wholeDocumentCoverage(), ChainStatus.TRUSTED, RevocationStatus.notChecked())
                .withVerdict(verdict, List.of());
    }

    private static SignatureReport signature(
            IntegrityStatus integrity, ByteRangeCoverage coverage, ChainStatus chainStatus, RevocationStatus revocation) {
        return new SignatureReport(
                "Signature1", "adbe.pkcs7.detached", coverage, integrity, null, TimestampInfo.absent(),
                List.of(), chainStatus, revocation, null);
    }

    private static ByteRangeCoverage wholeDocumentCoverage() {
        return ByteRangeCoverage.of(0, 10, 10, 90, 100);
    }

    private static ByteRangeCoverage partialCoverage() {
        return ByteRangeCoverage.of(0, 10, 10, 30, 100);
    }
}
