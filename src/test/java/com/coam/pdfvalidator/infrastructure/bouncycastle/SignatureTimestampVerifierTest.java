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

import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

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
}
