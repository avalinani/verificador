package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.TimestampInfo;
import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import com.coam.pdfvalidator.fixtures.TestPki;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises {@link SignatureTimestampVerifier} directly for the malformed-
 * token case: corrupting the unsigned {@code id-aa-signatureTimeStampToken}
 * attribute's value (rather than the whole PDF's bytes) is the precise way
 * to make only the timestamp parsing fail, without also disturbing the
 * outer CMS/{@code /ByteRange} structure {@link BcSignatureVerifierTest}
 * already covers for a genuinely valid timestamp.
 */
class SignatureTimestampVerifierTest {

    @Test
    void aMalformedTimestampTokenIsReportedInvalidWithoutThrowing() throws Exception {
        SignerInformation original = signerInformationWithTimestamp();

        AttributeTable existingUnsigned = original.getUnsignedAttributes();
        Hashtable<Object, Object> table = existingUnsigned.toHashtable();
        // Not a valid ContentInfo SEQUENCE: parsing this as a TimeStampToken must fail.
        Attribute garbageAttribute = new Attribute(
                PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(new ASN1Integer(12345)));
        table.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, garbageAttribute);

        SignerInformation corrupted =
                SignerInformation.replaceUnsignedAttributes(original, new AttributeTable(table));

        TimestampInfo result = SignatureTimestampVerifier.verify(corrupted, new BouncyCastleProvider());

        assertThat(result.isPresent()).isFalse();
        assertThat(result.imprintValid()).isFalse();
        assertThat(result.signatureValid()).isFalse();
        assertThat(result.noteOptional()).isPresent();
        assertThat(result.note()).contains("Malformed");
        // T23a: fixed text only -- no parser/exception detail reaches the report.
        assertThat(result.note()).isEqualTo("Malformed RFC 3161 timestamp token");
    }

    @Test
    void aTsaCertificateMissingTheTimestampingEkuIsNoted() throws Exception {
        SignerInformation original = signerInformationWithTimestamp();
        TimeStampToken token = extractToken(original);

        X509CertificateHolder originalTsaHolder =
                (X509CertificateHolder) token.getCertificates().getMatches(token.getSID()).iterator().next();
        X509Certificate originalTsaCertificate =
                new JcaX509CertificateConverter().getCertificate(originalTsaHolder);
        X509Certificate badTsaCertificate = TestPki.reissueWithoutTimestampingEku(originalTsaCertificate);

        CMSSignedData tokenWithBadCertificate = CMSSignedData.replaceCertificatesAndCRLs(
                token.toCMSSignedData(), new JcaCertStore(List.of(badTsaCertificate)), null, null);

        Hashtable<Object, Object> table = original.getUnsignedAttributes().toHashtable();
        table.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                        new DERSet(tokenWithBadCertificate.toASN1Structure())));
        SignerInformation modified =
                SignerInformation.replaceUnsignedAttributes(original, new AttributeTable(table));

        TimestampInfo result = SignatureTimestampVerifier.verify(modified, new BouncyCastleProvider());

        // The token's signed attributes bind it to the ORIGINAL certificate
        // (RFC 5035 ESSCertID/v2, checked by TimeStampToken#validate itself),
        // so validating against this substitute correctly fails too -- but
        // the missing-EKU check runs regardless, and must still be reported.
        assertThat(result.isPresent()).isTrue();
        assertThat(result.noteOptional()).isPresent();
        assertThat(result.note()).contains("timeStamping");
        // T23a: the signature failure is reported with a fixed text, never BC's own message.
        assertThat(result.note()).contains("TSA signature verification failed");
        assertThat(result.note()).doesNotContain("failed:").doesNotContain("certificate hash");
        assertThat(result.tsaTimeStampingEku()).isFalse();
        assertThat(result.trusted()).isFalse();
    }

    @Test
    void aGenuineTokenReportsTheTsaChainOrderedTsaFirstAndTheTimeStampingEku() throws Exception {
        SignerInformation original = signerInformationWithTimestamp();
        TimeStampToken token = extractToken(original);
        X509CertificateHolder tsaHolder =
                (X509CertificateHolder) token.getCertificates().getMatches(token.getSID()).iterator().next();

        TimestampInfo result = SignatureTimestampVerifier.verify(original, new BouncyCastleProvider());

        assertThat(result.tsaTimeStampingEku()).isTrue();
        assertThat(result.tsaChain()).hasSize(2);
        assertThat(result.tsaChain().get(0).encoded()).isEqualTo(tsaHolder.getEncoded());
        assertThat(result.tsaChain().get(0).subject()).contains("Spike Test TSA");
        assertThat(result.tsaChain().get(1).subject()).isEqualTo(result.tsaChain().get(1).issuer());
    }

    @Test
    void theAdapterNeverDeclaresATimestampTrustedItselfBecauseTrustIsDecidedByTheApplicationLayer() throws Exception {
        TimestampInfo result =
                SignatureTimestampVerifier.verify(signerInformationWithTimestamp(), new BouncyCastleProvider());

        assertThat(result.signatureValid()).isTrue();
        assertThat(result.trusted()).isFalse();
    }

    /**
     * Exercises {@link SignatureTimestampVerifier#mapTsaCertificate} directly
     * with a certificate double that fails to DER-re-encode -- the same
     * failure mode {@code X509CertificateInfoMapper.toDomain} already
     * documents as "not practically constructible" through a real, honestly
     * signed certificate (see {@code X509CertificateInfoMapperTest} and the
     * T04 progress notes). This proves the resilience fix directly: mapping
     * failure must be reported as a note, never thrown, so it cannot
     * silently discard the surrounding {@code genTime}/{@code imprintValid}/
     * {@code signatureValid} result the way it did before this fix (those
     * fields are computed independently of this mapping call in {@code
     * verifyToken}, and are unaffected by whatever this method returns).
     *
     * <p><b>T06b follow-up</b> ("add an integration-level assertion for the
     * TSA mapping-failure path through the public {@code verify} flow, if
     * feasible; otherwise document why"): attempted and confirmed
     * infeasible. Swapping a real, embedded TSA certificate for a Mockito
     * double that fails only on {@code getEncoded()} -- the same technique
     * {@link #aTsaCertificateMissingTheTimestampingEkuIsNoted()} uses to
     * substitute a certificate into a real token -- does not reach {@code
     * verify()} at all: rebuilding the token's certificate store with {@code
     * JcaCertStore} itself calls {@code getEncoded()} on every certificate
     * to construct the underlying ASN.1 structure, so the double's stub
     * throws right there, before the substituted token can even be
     * assembled. A real {@code X509CertificateHolder}-derived certificate
     * (the only kind {@code findTsaCertificate} ever hands to {@code
     * mapTsaCertificate} through the public flow) always re-encodes
     * successfully by construction, since {@code getEncoded()} just returns
     * the same bytes the holder itself was built from -- so this mapping
     * failure genuinely cannot occur except through a certificate double,
     * which is exactly what this seam-level test already exercises directly.
     */
    @Test
    void aTsaCertificateMappingFailureIsReportedAsANoteInsteadOfThrowing() throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal("CN=Unmappable TSA"));
        when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=Unmappable TSA"));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.ONE);
        when(certificate.getNotBefore()).thenReturn(Date.from(java.time.Instant.EPOCH));
        when(certificate.getNotAfter()).thenReturn(Date.from(java.time.Instant.EPOCH.plusSeconds(3600)));
        when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
        when(certificate.getEncoded()).thenThrow(new CertificateEncodingException("boom"));

        SignatureTimestampVerifier.CertificateMapping mapping =
                SignatureTimestampVerifier.mapTsaCertificate(certificate);

        assertThat(mapping.certificateInfo()).isNull();
        assertThat(mapping.failureNote()).isEqualTo("TSA certificate data could not be mapped");
    }

    /** T23a: an exception whose message carries attacker-style text never reaches the note. */
    @Test
    void aTsaCertificateMappingFailureNeverExposesTheExceptionMessage() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal())
                .thenThrow(new IllegalStateException("MARKER\ncom.evil.FakeException: injected"));

        SignatureTimestampVerifier.CertificateMapping mapping =
                SignatureTimestampVerifier.mapTsaCertificate(certificate);

        assertThat(mapping.certificateInfo()).isNull();
        assertThat(mapping.failureNote())
                .isEqualTo("TSA certificate data could not be mapped")
                .doesNotContain("MARKER").doesNotContain("FakeException").doesNotContain("\n");
    }

    @Test
    void noUnsignedAttributeAtAllIsReportedAbsent() throws Exception {
        SignerInformation signed = signerInformationWithoutTimestamp();

        TimestampInfo result = SignatureTimestampVerifier.verify(signed, new BouncyCastleProvider());

        assertThat(result).isEqualTo(TimestampInfo.absent());
    }

    /** The real {@link SignerInformation} extracted from a {@link TestPdfFactory#signedWithTimestamp()} fixture. */
    private static SignerInformation signerInformationWithTimestamp() throws Exception {
        return firstSignerInformation(TestPdfFactory.signedWithTimestamp());
    }

    private static SignerInformation signerInformationWithoutTimestamp() throws Exception {
        return firstSignerInformation(TestPdfFactory.signed());
    }

    private static SignerInformation firstSignerInformation(byte[] pdf) throws Exception {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            PDSignature signature = document.getSignatureFields().get(0).getSignature();
            // The /Contents COSString is zero-padded to the reserved
            // preferredSignatureSize, so a single ASN1Primitive must be read
            // (ignoring the trailing padding) rather than passed to
            // CMSSignedData's byte[] constructor directly -- same gotcha as
            // CmsSignatureVerification.readContentInfo.
            byte[] cmsDer = signature.getContents();
            ContentInfo contentInfo;
            try (ASN1InputStream asn1In = new ASN1InputStream(cmsDer)) {
                ASN1Primitive object = asn1In.readObject();
                contentInfo = ContentInfo.getInstance(object);
            }
            CMSSignedData signedData = new CMSSignedData(contentInfo);
            return signedData.getSignerInfos().getSigners().iterator().next();
        }
    }

    /** Re-extracts the embedded {@link TimeStampToken} from a signer's unsigned attribute, mirroring production. */
    private static TimeStampToken extractToken(SignerInformation signerInformation) throws Exception {
        Attribute attribute =
                signerInformation.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        ContentInfo contentInfo = ContentInfo.getInstance(attribute.getAttributeValues()[0]);
        return new TimeStampToken(contentInfo);
    }

    /** T23a: the log copy of a failure is one flat line, so hostile parser text cannot forge log entries. */
    @Test
    void logTextOfAFailureIsFlattenedToOneLine() {
        String logged = SignatureTimestampVerifier.sanitizeForLog(
                new IllegalStateException("MARKER\r\n2026-01-01 FORGED ENTRY\u0000 LINE PARA\u0085NEL" + "x".repeat(1000)));

        assertThat(logged).doesNotContain("\n").doesNotContain("\r").doesNotContain("\u0000")
                .doesNotContain(" ").doesNotContain(" ").doesNotContain("\u0085");
        assertThat(logged).contains("java.lang.IllegalStateException: MARKER").hasSizeLessThanOrEqualTo(303);
    }
}
