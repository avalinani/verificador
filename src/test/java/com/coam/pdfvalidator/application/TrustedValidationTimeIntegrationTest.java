package com.coam.pdfvalidator.application;

import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.OverallVerdict;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.SignatureVerdict;
import com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy;
import com.coam.pdfvalidator.fixtures.TestPdfSigner;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.infrastructure.bouncycastle.BcSignatureVerifier;
import com.coam.pdfvalidator.infrastructure.crypto.JcaHashCalculator;
import com.coam.pdfvalidator.infrastructure.pdfbox.PdfBoxDocumentReader;
import com.coam.pdfvalidator.infrastructure.pki.PkixCertificateChainValidator;
import com.coam.pdfvalidator.infrastructure.pki.TrustAnchorProvider;
import com.coam.pdfvalidator.infrastructure.preflight.PreflightPdfaValidator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T19: which instant the signer chain is validated at, with real Bouncy
 * Castle / PKIX adapters and real certificates. The signer certificate in
 * these tests expired two days ago (its key is still in the attacker's
 * hands, the classic scenario); what changes between tests is only the
 * timestamp, or the date the signer claims.
 */
class TrustedValidationTimeIntegrationTest {

    private static final Duration THIRTY_DAYS = Duration.ofDays(30);

    @Test
    void aForgedTimestampFromAnUntrustedTsaDoesNotMakeAnExpiredSignerValid() throws Exception {
        TestPki.IssuedIdentity expiredSigner = TestPki.issueExpiredSigner();
        TestPki.TsaIdentity attackerTsa = TestPki.issueTsaIdentity(Duration.ofDays(60)); // self-made root, not in the trust store
        byte[] pdf = TestPdfSigner.signWithTimestamp(
                TestPdfSigner.createSimplePdf(), expiredSigner, attackerTsa, Instant.now().minus(THIRTY_DAYS));

        SignatureReport signature = analyze(pdf, expiredSigner).signatures().get(0);

        assertThat(signature.timestamp().imprintValid()).isTrue();
        assertThat(signature.timestamp().signatureValid()).isTrue();
        assertThat(signature.timestamp().trusted()).isFalse();
        assertThat(signature.timestamp().note()).contains("TSA not trusted");
        assertThat(signature.chainStatus()).isEqualTo(ChainStatus.EXPIRED);
        assertThat(signature.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
        assertThat(signature.verdictReasons()).contains(
                SignatureVerdictPolicy.REASON_VALIDATED_AT_CURRENT_TIME, SignatureVerdictPolicy.REASON_CHAIN_EXPIRED);
    }

    @Test
    void theDateTheSignerClaimsIsReportedButNeverUsedToValidateTheChain() throws Exception {
        TestPki.IssuedIdentity expiredSigner = TestPki.issueExpiredSigner();
        Instant claimed = Instant.now().minus(THIRTY_DAYS);
        byte[] pdf = TestPdfSigner.signClaimingTime(TestPdfSigner.createSimplePdf(), expiredSigner, claimed);

        PdfAnalysisReport report = analyze(pdf, expiredSigner);

        SignatureReport signature = report.signatures().get(0);
        assertThat(signature.claimedSigningTime()).isBefore(Instant.now().minus(Duration.ofDays(29)));
        assertThat(signature.timestamp().isPresent()).isFalse();
        assertThat(signature.chainStatus()).isEqualTo(ChainStatus.EXPIRED);
        assertThat(signature.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
        assertThat(signature.verdictReasons()).contains(SignatureVerdictPolicy.REASON_VALIDATED_AT_CURRENT_TIME);
        assertThat(SignatureVerdictPolicy.overallVerdict(report.signatures())).isEqualTo(OverallVerdict.NOT_ADMITTED);
    }

    @Test
    void aTimestampFromATrustedTsaValidatesAnExpiredSignerAtItsGenTime() throws Exception {
        TestPki.IssuedIdentity expiredSigner = TestPki.issueExpiredSigner();
        TestPki.TsaIdentity trustedTsa = TestPki.issueTsaIdentityUnder(expiredSigner);
        byte[] pdf = TestPdfSigner.signWithTimestamp(
                TestPdfSigner.createSimplePdf(), expiredSigner, trustedTsa, Instant.now().minus(THIRTY_DAYS));

        SignatureReport signature = analyze(pdf, expiredSigner).signatures().get(0);

        assertThat(signature.timestamp().trusted()).isTrue();
        assertThat(signature.chainStatus()).isEqualTo(ChainStatus.TRUSTED);
        assertThat(signature.verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(signature.verdictReasons()).doesNotContain(SignatureVerdictPolicy.REASON_VALIDATED_AT_CURRENT_TIME);
    }

    @Test
    void aGenTimeInTheFutureIsNotTrustedEvenFromATrustedTsa() throws Exception {
        TestPki.IssuedIdentity expiredSigner = TestPki.issueExpiredSigner();
        TestPki.TsaIdentity trustedTsa = TestPki.issueTsaIdentityUnder(expiredSigner);
        byte[] pdf = TestPdfSigner.signWithTimestamp(
                TestPdfSigner.createSimplePdf(), expiredSigner, trustedTsa, Instant.now().plus(Duration.ofHours(1)));

        SignatureReport signature = analyze(pdf, expiredSigner).signatures().get(0);

        assertThat(signature.timestamp().trusted()).isFalse();
        assertThat(signature.timestamp().note()).contains("future");
        assertThat(signature.chainStatus()).isEqualTo(ChainStatus.EXPIRED);
        assertThat(signature.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
    }

    @Test
    void aGenTimeBeforeTheTsaCertificateWasValidIsNotTrusted() throws Exception {
        TestPki.IssuedIdentity expiredSigner = TestPki.issueExpiredSigner();
        TestPki.TsaIdentity trustedTsa = TestPki.issueTsaIdentityUnder(expiredSigner); // valid from 450 days ago
        byte[] pdf = TestPdfSigner.signWithTimestamp(
                TestPdfSigner.createSimplePdf(), expiredSigner, trustedTsa, Instant.now().minus(Duration.ofDays(480)));

        SignatureReport signature = analyze(pdf, expiredSigner).signatures().get(0);

        // Bouncy Castle already rejects a token whose TSA certificate was not valid at genTime.
        assertThat(signature.timestamp().signatureValid()).isFalse();
        assertThat(signature.timestamp().trusted()).isFalse();
        assertThat(signature.timestamp().note()).contains("TSA not trusted");
        assertThat(signature.verdict()).isEqualTo(SignatureVerdict.NOT_ADMITTED);
    }

    private static PdfAnalysisReport analyze(byte[] pdf, TestPki.IssuedIdentity trustedRootOwner) throws IOException {
        AnalyzePdfUseCase useCase = new AnalyzePdfUseCase(
                new JcaHashCalculator(),
                new PdfBoxDocumentReader(),
                new BcSignatureVerifier(),
                new PkixCertificateChainValidator(TrustAnchorProvider.of(trustedRootOwner.rootCertificate())),
                new PreflightPdfaValidator(),
                new NoOpRevocationChecker(),
                Clock.systemUTC());
        return useCase.analyze("t.pdf", pdf, new AnalysisOptions(false));
    }
}
