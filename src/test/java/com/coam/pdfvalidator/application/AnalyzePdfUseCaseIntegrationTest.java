package com.coam.pdfvalidator.application;

import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.fixtures.TestPdfSigner;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.infrastructure.bouncycastle.BcSignatureVerifier;
import com.coam.pdfvalidator.infrastructure.crypto.JcaHashCalculator;
import com.coam.pdfvalidator.infrastructure.pdfbox.PdfBoxDocumentReader;
import com.coam.pdfvalidator.infrastructure.pki.PkixCertificateChainValidator;
import com.coam.pdfvalidator.infrastructure.pki.TrustAnchorProvider;
import com.coam.pdfvalidator.infrastructure.preflight.PreflightPdfaValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The one integration test for {@link AnalyzePdfUseCase}: every real
 * adapter wired together (no fakes), against {@link
 * TestPdfSigner#signWithTimestamp} -- the same construction {@code
 * TestPdfFactory.signedWithTimestamp()} itself calls internally, used
 * directly here (rather than through that convenience method) only so this
 * test can also keep the {@link TestPki.IssuedIdentity} used to sign it, to
 * build a trust store that actually trusts its root -- and a trust store
 * containing exactly that root, asserting the full report comes back
 * coherent end to end: intact integrity, a trusted chain, and a valid
 * signature timestamp.
 */
class AnalyzePdfUseCaseIntegrationTest {

    @Test
    void aValidlySignedAndTimestampedPdfProducesACoherentFullReport() throws Exception {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        TestPki.TsaIdentity tsaIdentity = TestPki.issueTsaIdentityUnder(identity);
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        byte[] pdf = TestPdfSigner.signWithTimestamp(unsigned, identity, tsaIdentity);

        TrustAnchorProvider trustAnchorProvider = TrustAnchorProvider.of(identity.rootCertificate());
        AnalyzePdfUseCase useCase = new AnalyzePdfUseCase(
                new JcaHashCalculator(),
                new PdfBoxDocumentReader(),
                new BcSignatureVerifier(),
                new PkixCertificateChainValidator(trustAnchorProvider),
                new PreflightPdfaValidator(),
                new NoOpRevocationChecker(),
                Clock.systemUTC());

        PdfAnalysisReport report = useCase.analyze("signed-with-timestamp.pdf", pdf, new AnalysisOptions(false));

        assertThat(report.fileName()).isEqualTo("signed-with-timestamp.pdf");
        assertThat(report.sizeBytes()).isEqualTo(pdf.length);
        assertThat(report.hashes().sha256()).hasSize(64);
        assertThat(report.structure().pageCount()).isEqualTo(1);

        assertThat(report.signatures()).hasSize(1);
        SignatureReport signature = report.signatures().get(0);
        assertThat(signature.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(signature.coverage().coversWholeDocument()).isTrue();
        assertThat(signature.chainStatus()).isEqualTo(ChainStatus.TRUSTED);
        assertThat(signature.revocation().state()).isEqualTo(RevocationState.NOT_CHECKED);
        assertThat(signature.anomalyOptional()).isEmpty();

        assertThat(signature.timestamp().isPresent()).isTrue();
        assertThat(signature.timestamp().imprintValid()).isTrue();
        assertThat(signature.timestamp().signatureValid()).isTrue();
        // The TSA is issued under the same trusted root: the timestamp itself is trusted (T19).
        assertThat(signature.timestamp().trusted()).isTrue();
        assertThat(signature.verdict()).isEqualTo(com.coam.pdfvalidator.domain.model.SignatureVerdict.VALID);
    }
}
