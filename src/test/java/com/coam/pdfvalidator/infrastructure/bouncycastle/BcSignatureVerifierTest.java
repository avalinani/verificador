package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import com.coam.pdfvalidator.fixtures.TestPdfSigner;
import com.coam.pdfvalidator.fixtures.TestPki;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

        // T11f: subject/issuer are rendered by X509CertificateInfoMapper's own
        // BCStyle-based formatting (readable, decodes every attribute BCStyle
        // recognizes), not by X500Principal#getName()'s JDK RFC 2253
        // rendering -- for this fixture's plain CN/O/C subject, the two only
        // ever differ in whether they happen to agree on attribute order.
        assertThat(signerInfo.subject()).isEqualTo("CN=Spike Test Signer,O=COAM,C=ES");
        assertThat(signerInfo.commonName()).isEqualTo("Spike Test Signer");
        assertThat(new BigInteger(signerInfo.serialNumberHex(), 16))
                .isEqualTo(identity.endEntityCertificate().getSerialNumber());
        assertThat(signerInfo.notBefore()).isEqualTo(identity.endEntityCertificate().getNotBefore().toInstant());
        assertThat(signerInfo.notAfter()).isEqualTo(identity.endEntityCertificate().getNotAfter().toInstant());

        assertThat(issuerInfo.subject())
                .as("chain is ordered signer first, then issuer")
                .isEqualTo("CN=Spike Test Root CA,O=COAM,C=ES");
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
        SignatureReport report = reports.get(0);
        assertThat(report.integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
        assertThat(report.anomalyOptional())
                .as("a tampered digest must still report a human-readable reason (T09c)")
                .contains("messageDigest does not match the signed bytes");
        assertThat(report.chain())
                .as("the CMS itself parsed fine (only the digest mismatched), so the chain must still be extracted")
                .hasSize(2);
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
        // T09d follow-up (review advisory): a structural /ByteRange failure
        // must always carry a stable, non-null reason, never leave anomaly
        // unset.
        assertThat(reports.get(0).anomalyOptional()).isPresent();
    }

    @Test
    void aNegativeByteRangeLengthIsInvalidNotAnException() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithNegativeByteRangeLength();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
        assertThat(reports.get(0).anomalyOptional()).isPresent();
    }

    @Test
    void anUnsupportedSubFilterIsReportedAsUnsupported() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithSubFilter("adbe.pkcs7.sha1");

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.UNSUPPORTED);
        assertThat(reports.get(0).subFilter()).isEqualTo("adbe.pkcs7.sha1");
        assertThat(reports.get(0).anomalyOptional())
                .as("UNSUPPORTED must also carry a human-readable reason (T09c)")
                .isPresent();
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

    @Test
    void aSignatureFieldThatThrowsWhileBeingReadIsReportedInvalidNotAnException() {
        // Reproduces a previous bug: only the CMS/ByteRange evaluation was
        // guarded against a RuntimeException, not the earlier PDFBox reads
        // (getSignature()/getFullyQualifiedName()) done per field.
        PDSignatureField hostileField = mock(PDSignatureField.class);
        when(hostileField.getSignature()).thenThrow(new IllegalStateException("boom"));

        SignatureReport report = verifier.evaluateField(new byte[] {1, 2, 3}, hostileField);

        assertThat(report).isNotNull();
        assertThat(report.integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
    }

    @Test
    void anUnsignedFieldReportsNothing() {
        PDSignatureField unsignedField = mock(PDSignatureField.class);
        when(unsignedField.getSignature()).thenReturn(null);

        assertThat(verifier.evaluateField(new byte[] {1, 2, 3}, unsignedField)).isNull();
    }

    @Test
    void aSignatureWithoutATimestampReportsItAbsent() throws Exception {
        byte[] pdf = TestPdfFactory.signed();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports.get(0).timestamp().isPresent()).isFalse();
        assertThat(reports.get(0).timestamp()).isEqualTo(TimestampInfo.absent());
    }

    @Test
    void aValidSignatureTimestampIsVerified() throws Exception {
        Instant beforeSigning = Instant.now().minusSeconds(5);
        byte[] pdf = TestPdfFactory.signedWithTimestamp();
        Instant afterSigning = Instant.now().plusSeconds(5);

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        SignatureReport report = reports.get(0);
        assertThat(report.integrity()).isEqualTo(IntegrityStatus.INTACT);

        TimestampInfo timestamp = report.timestamp();
        assertThat(timestamp.isPresent()).isTrue();
        assertThat(timestamp.genTime()).isBetween(beforeSigning, afterSigning);
        assertThat(timestamp.tsaName()).contains("Spike Test TSA");
        assertThat(timestamp.imprintValid()).isTrue();
        assertThat(timestamp.signatureValid()).isTrue();
        assertThat(timestamp.tsaCertificateOptional()).isPresent();
        assertThat(timestamp.noteOptional()).isEmpty();
    }

    @Test
    void aTimestampWithTheWrongImprintIsInvalidButTheSignatureIsStillIntact() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithTamperedTimestamp();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        SignatureReport report = reports.get(0);
        assertThat(report.integrity())
                .as("an invalid embedded timestamp must not affect the signature's own integrity")
                .isEqualTo(IntegrityStatus.INTACT);

        TimestampInfo timestamp = report.timestamp();
        assertThat(timestamp.isPresent()).isTrue();
        assertThat(timestamp.imprintValid()).isFalse();
        assertThat(timestamp.signatureValid())
                .as("the TSA's own CMS signature over the (wrongly-imprinted) token is still valid")
                .isTrue();
    }

    /**
     * T09c, real-world case 1 (Camerfirma): a signature whose signer
     * certificate had already expired by the time the document was signed
     * must still report cryptographic integrity independently of that fact.
     * Bouncy Castle's own {@code SignerInformation#verify}, when built from
     * an {@code X509CertificateHolder} rather than a bare public key, throws
     * {@code CMSVerifierCertificateNotValidException} in exactly this case
     * -- verified as genuine RED against the pre-fix code below.
     */
    @Test
    void aCertificateExpiredAtSigningTimeIsIntactWithAnAnomalyNoteAndANonEmptyChain() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithCertificateExpiredAtSigningTime();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        SignatureReport report = reports.get(0);
        assertThat(report.integrity())
                .as("crypto integrity must not depend on the signer certificate's own validity")
                .isEqualTo(IntegrityStatus.INTACT);
        assertThat(report.anomalyOptional())
                .as("the certificate's own invalidity at signing time must still be surfaced")
                .hasValueSatisfying(anomaly -> assertThat(anomaly)
                        .contains("signer certificate was not valid at the declared signing time"));
        assertThat(report.chain()).hasSize(2);
    }

    /**
     * T09c, real-world case 2 (FNMT): a CMS whose {@code SignerInfo} encodes
     * a SIGNATURE algorithm OID ({@code sha256WithRSAEncryption}) in its
     * {@code digestAlgorithm} field instead of the plain digest OID -- a
     * non-standard encoding Adobe accepts, which Bouncy Castle's default
     * digest lookup otherwise rejects with {@code NoSuchAlgorithmException}
     * -- verified as genuine RED against the pre-fix code below.
     */
    @Test
    void aSignatureAlgorithmOidUsedAsDigestAlgorithmIsToleratedWithAnAnomalyNote() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithSignatureAlgorithmOidAsDigestOid();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        SignatureReport report = reports.get(0);
        assertThat(report.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(report.anomalyOptional())
                .hasValueSatisfying(anomaly -> assertThat(anomaly)
                        .contains("non-standard digestAlgorithm encoding"));
    }

    /**
     * T09d follow-up (review advisory): the mislabeled-digest bypass in
     * {@code CmsSignatureVerification#verifyWithMislabeledDigestAlgorithm}
     * must not become a way to skip tamper detection -- a byte flipped
     * after signing (same technique as {@link #aTamperedSignedByteIsAnInvalidSignature}
     * above) must still be reported {@code INVALID_SIGNATURE}, exactly as
     * it would be for a standard CMS.
     */
    @Test
    void aTamperedSignatureAlgorithmOidUsedAsDigestAlgorithmIsInvalid() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithSignatureAlgorithmOidAsDigestOidThenTampered();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
    }

    /**
     * T09d follow-up (review advisory): the same mislabeled-{@code
     * digestAlgorithm} case as {@link
     * #aSignatureAlgorithmOidUsedAsDigestAlgorithmIsToleratedWithAnAnomalyNote},
     * but with signed attributes present -- exercising {@code
     * verifyWithMislabeledDigestAlgorithm}'s other branch (checking the
     * signed {@code messageDigest} attribute first, then verifying over the
     * signed attributes' DER encoding rather than the raw content).
     */
    @Test
    void aSignatureAlgorithmOidUsedAsDigestAlgorithmWithSignedAttributesIsToleratedWithAnAnomalyNote()
            throws Exception {
        byte[] pdf = TestPdfFactory.signedWithSignatureAlgorithmOidAsDigestOidAndSignedAttributes();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        SignatureReport report = reports.get(0);
        assertThat(report.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(report.anomalyOptional())
                .hasValueSatisfying(anomaly -> assertThat(anomaly)
                        .contains("non-standard digestAlgorithm encoding"));
    }

    /**
     * T10 follow-up (T09d review advisory): {@code
     * BcSignatureVerifier#byteRangeFailureReason} is a package-private seam
     * specifically so this fallback -- taken only when an {@code
     * IllegalArgumentException} from {@code SignatureByteRange}/{@code
     * ByteRangeCoverage} carries no message at all -- can be unit-tested
     * directly. It is currently unreachable through any real PDF (every
     * throw site in those two classes always supplies a message), so this
     * test constructs the exception by hand rather than trying to drive a
     * real file through it.
     */
    @Test
    void theByteRangeFailureFallbackReasonIsUsedWhenTheExceptionCarriesNoMessage() {
        assertThat(BcSignatureVerifier.byteRangeFailureReason(new IllegalArgumentException()))
                .isEqualTo("invalid /ByteRange");
    }

    @Test
    void theByteRangeFailureReasonIsTheExceptionsOwnMessageWhenPresent() {
        assertThat(BcSignatureVerifier.byteRangeFailureReason(new IllegalArgumentException("ByteRange gap is out of bounds")))
                .isEqualTo("ByteRange gap is out of bounds");
    }

    /**
     * T09d review advisory: the mislabeled-digest bypass's signed-attributes
     * branch ({@code
     * CmsSignatureVerification#verifyWithMislabeledDigestAlgorithm}, the
     * path that checks {@code messageDigest} first before verifying over
     * the signed attributes) had a tampered-content negative only for the
     * no-signed-attributes variant ({@code
     * aTamperedSignatureAlgorithmOidUsedAsDigestAlgorithmIsInvalid} above).
     * This covers the same tamper for the signed-attributes variant.
     */
    @Test
    void aTamperedSignatureAlgorithmOidUsedAsDigestAlgorithmWithSignedAttributesIsInvalid() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithSignatureAlgorithmOidAsDigestOidAndSignedAttributesThenTampered();

        List<SignatureReport> reports = verifier.verify(pdf);

        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).integrity()).isEqualTo(IntegrityStatus.INVALID_SIGNATURE);
    }

    // A TSA certificate missing the timeStamping EKU is covered by
    // SignatureTimestampVerifierTest instead: Bouncy Castle's own
    // TimeStampTokenGenerator refuses to issue such a token at all, so that
    // scenario can only be produced by substituting an already-issued
    // token's certificate (see SignatureTimestampVerifierTest and
    // TestPki#reissueWithoutTimestampingEku), which needs BC types this
    // black-box test does not otherwise depend on.
}
