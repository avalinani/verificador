package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import com.coam.pdfvalidator.fixtures.TestPdfSigner;
import com.coam.pdfvalidator.fixtures.TestPki;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BcSignatureVerifierTest {

    private final BcSignatureVerifier verifier = new BcSignatureVerifier();

    @Test
    void anUnsignedPdfHasNoSignatures() throws Exception {
        byte[] pdf = TestPdfFactory.unsigned();

        assertThat(verifier.verify(pdf)).isEmpty();
    }

    @Test
    void aSignedPdfIsReportedIntactWithItsCertificateChain() throws Exception {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        byte[] pdf = TestPdfSigner.sign(unsigned, identity);

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        SignatureReport report = reports.get(0);
        assertThat(report.subFilter()).isEqualTo(PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName());
        assertThat(report.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(report.coverage().coversWholeDocument()).isTrue();
        assertThat(report.chainStatus()).isEqualTo(ChainStatus.NOT_CHECKED);
        assertThat(report.revocation().state()).isEqualTo(RevocationState.NOT_CHECKED);

        assertThat(report.chain()).hasSize(2);
        CertificateInfo signerInfo = report.chain().get(0);
        CertificateInfo issuerInfo = report.chain().get(1);

        assertThat(signerInfo.subject())
                .isEqualTo(identity.endEntityCertificate().getSubjectX500Principal().getName());
        assertThat(new BigInteger(signerInfo.serialNumberHex(), 16))
                .isEqualTo(identity.endEntityCertificate().getSerialNumber());
        assertThat(signerInfo.notBefore()).isEqualTo(identity.endEntityCertificate().getNotBefore().toInstant());
        assertThat(signerInfo.notAfter()).isEqualTo(identity.endEntityCertificate().getNotAfter().toInstant());

        assertThat(issuerInfo.subject())
                .as("chain is ordered signer first, then issuer")
                .isEqualTo(identity.rootCertificate().getSubjectX500Principal().getName());
    }

    @Test
    void theSignerCertificatesOcspAndCrlUrlsAreExtracted() throws Exception {
        byte[] pdf = TestPdfFactory.signed();

        List<SignatureReport> reports = verifier.verify(pdf);

        CertificateInfo signerInfo = reports.get(0).chain().get(0);
        assertThat(signerInfo.ocspUrls()).contains("http://ocsp.example.org/ee");
        assertThat(signerInfo.crlUrls()).contains("http://crl.example.org/ee.crl");
    }

    @Test
    void aSignatureFollowedByAnIncrementalUpdateIsModifiedAfterSigning() throws Exception {
        byte[] pdf = TestPdfFactory.signedThenIncrementallyModified();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.MODIFIED_AFTER_SIGNING);
        assertThat(reports.get(0).coverage().coversWholeDocument()).isFalse();
    }

    @Test
    void aTamperedSignedByteIsAnInvalidSignature() throws Exception {
        byte[] pdf = TestPdfFactory.signedThenTampered();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
    }

    @Test
    void aDoublySignedPdfReportsTheFirstSignatureAsModifiedAndTheSecondAsIntact() throws Exception {
        byte[] pdf = TestPdfFactory.doublySigned();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(2);
        assertThat(reports.get(0).integrity())
                .as("the first signature's revision ends before the second signature was appended")
                .isEqualTo(IntegrityStatus.MODIFIED_AFTER_SIGNING);
        assertThat(reports.get(1).integrity())
                .as("the second (last) signature covers up to the actual end of the file")
                .isEqualTo(IntegrityStatus.INTACT);
    }

    @Test
    void aByteRangeExceedingTheFileLengthIsInvalidNotAnException() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithByteRangeExceedingFileLength();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
    }

    @Test
    void aNegativeByteRangeLengthIsInvalidNotAnException() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithNegativeByteRangeLength();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
    }

    @Test
    void anUnsupportedSubFilterIsReportedAsUnsupported() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithSubFilter("adbe.pkcs7.sha1");

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.UNSUPPORTED);
        assertThat(reports.get(0).subFilter()).isEqualTo("adbe.pkcs7.sha1");
    }

    @Test
    void aDocumentTimestampSubFilterIsReportedAsUnsupportedForNow() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithSubFilter("ETSI.RFC3161");

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity())
                .as("document timestamps are handled in a later task (T05), not verified here")
                .isEqualTo(IntegrityStatus.UNSUPPORTED);
    }

    @Test
    void corruptBytesRaiseInvalidPdfException() throws Exception {
        byte[] pdf = TestPdfFactory.corrupt();

        assertThatThrownBy(() -> verifier.verify(pdf)).isInstanceOf(InvalidPdfException.class);
    }
}
