package com.coam.pdfvalidator.application;

import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import com.coam.pdfvalidator.fixtures.TestPdfSigner;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.infrastructure.bouncycastle.BcSignatureVerifier;
import com.coam.pdfvalidator.infrastructure.bouncycastle.SignatureLimits;
import com.coam.pdfvalidator.infrastructure.crypto.JcaHashCalculator;
import com.coam.pdfvalidator.infrastructure.pdfbox.PdfBoxDocumentReader;
import com.coam.pdfvalidator.infrastructure.pki.PkixCertificateChainValidator;
import com.coam.pdfvalidator.infrastructure.pki.TrustAnchorProvider;
import com.coam.pdfvalidator.infrastructure.preflight.PreflightPdfaValidator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T26a: the TSA certificate of a timestamp token requested with {@code certReq=false} (so the token carries no
 * certificate) is looked up in the signature's own CMS and in the configured trust anchors, matched strictly by the
 * token's signer identifier and its ESSCertID hash. Real Bouncy Castle / PKIX adapters, real certificates.
 */
class TsaCertificateLookupIntegrationTest {

    private static final String NOT_FOUND = "TSA certificate not found in the timestamp token";

    @Test
    void aCertificateLessTokenIsTrustedWhenTheTsaCertificateIsInTheSignatureCms() throws Exception {
        TestPki.IssuedIdentity signer = TestPki.issueSigningIdentity();
        TestPki.TsaIdentity tsa = TestPki.issueTsaIdentityUnder(signer);
        byte[] pdf = TestPdfSigner.signWithCertificateLessTimestamp(
                TestPdfSigner.createSimplePdf(), signer, tsa, List.of(tsa.certificate()));

        TimestampInfo timestamp = timestampOf(pdf, TrustAnchorProvider.of(signer.rootCertificate()));

        assertThat(timestamp.signatureValid()).isTrue();
        assertThat(timestamp.tsaTimeStampingEku()).isTrue();
        assertThat(timestamp.trusted()).isTrue();
        assertThat(timestamp.noteOptional()).isEmpty();
    }

    @Test
    void aCertificateLessTokenIsTrustedWhenTheTsaCertificateIsOnlyATrustAnchor() throws Exception {
        TestPki.IssuedIdentity signer = TestPki.issueSigningIdentity();
        TestPki.TsaIdentity tsa = TestPki.issueTsaIdentityUnder(signer);
        byte[] pdf = TestPdfSigner.signWithCertificateLessTimestamp(
                TestPdfSigner.createSimplePdf(), signer, tsa, List.of());

        TimestampInfo timestamp = timestampOf(pdf, TrustAnchorProvider.of(signer.rootCertificate(), tsa.certificate()));

        assertThat(timestamp.signatureValid()).isTrue();
        assertThat(timestamp.trusted()).isTrue();
    }

    @Test
    void aSameSubjectCertificateWithAnotherSerialAndKeyIsNeverSubstituted() throws Exception {
        TestPki.IssuedIdentity signer = TestPki.issueSigningIdentity();
        TestPki.TsaIdentity realTsa = TestPki.issueTsaIdentityUnder(signer);
        TestPki.TsaIdentity lookAlike = TestPki.issueTsaIdentityUnder(signer); // same subject, new key and serial
        byte[] pdf = TestPdfSigner.signWithCertificateLessTimestamp(
                TestPdfSigner.createSimplePdf(), signer, realTsa, List.of(lookAlike.certificate()));

        TimestampInfo timestamp =
                timestampOf(pdf, TrustAnchorProvider.of(signer.rootCertificate(), lookAlike.certificate()));

        assertThat(timestamp.signatureValid()).isFalse();
        assertThat(timestamp.trusted()).isFalse();
        assertThat(timestamp.note()).contains(NOT_FOUND);
    }

    @Test
    void aCertificateWithTheSameIdentifierButDifferentContentFailsTheEssCertIdBinding() throws Exception {
        TestPki.IssuedIdentity signer = TestPki.issueSigningIdentity();
        TestPki.TsaIdentity realTsa = TestPki.issueTsaIdentityUnder(signer);
        // Same issuer, serial and public key (so the signer identifier matches) but different content.
        X509Certificate forged = TestPki.reissueWithoutTimestampingEku(realTsa.certificate());
        byte[] pdf = TestPdfSigner.signWithCertificateLessTimestamp(
                TestPdfSigner.createSimplePdf(), signer, realTsa, List.of(forged));

        TimestampInfo timestamp = timestampOf(pdf, TrustAnchorProvider.of(signer.rootCertificate()));

        assertThat(timestamp.trusted()).isFalse();
        assertThat(timestamp.note()).contains(NOT_FOUND);
    }

    @Test
    void aCertificateLessTokenWhoseTsaCertificateIsNowhereKeepsTheNotFoundBehaviour() throws Exception {
        TestPki.IssuedIdentity signer = TestPki.issueSigningIdentity();
        TestPki.TsaIdentity tsa = TestPki.issueTsaIdentityUnder(signer);
        byte[] pdf = TestPdfSigner.signWithCertificateLessTimestamp(
                TestPdfSigner.createSimplePdf(), signer, tsa, List.of());

        TimestampInfo timestamp = timestampOf(pdf, TrustAnchorProvider.of(signer.rootCertificate()));

        assertThat(timestamp.isPresent()).isTrue();
        assertThat(timestamp.signatureValid()).isFalse();
        assertThat(timestamp.trusted()).isFalse();
        assertThat(timestamp.note()).contains(NOT_FOUND);
    }

    private static TimestampInfo timestampOf(byte[] pdf, TrustAnchorProvider anchors) throws IOException {
        AnalyzePdfUseCase useCase = new AnalyzePdfUseCase(
                new JcaHashCalculator(),
                new PdfBoxDocumentReader(),
                new BcSignatureVerifier(SignatureLimits.DEFAULT, anchors),
                new PkixCertificateChainValidator(anchors),
                new PreflightPdfaValidator(),
                new NoOpRevocationChecker(),
                Clock.systemUTC());
        PdfAnalysisReport report = useCase.analyze("t.pdf", pdf, new AnalysisOptions(false));
        return report.signatures().get(0).timestamp();
    }
}
