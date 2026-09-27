package com.coam.pdfvalidator.fixtures;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

/**
 * Test-only helper that creates a minimal one-page PDF with PDFBox and signs
 * it with a detached CAdES (CMS) signature built with Bouncy Castle. Mirrors
 * the mechanics that a future production signer would use, but stays in the
 * test sources on purpose: this is a spike, not the real implementation.
 */
public final class TestPdfSigner {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestPdfSigner() {
    }

    public static byte[] createSimplePdf() throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                contentStream.beginText();
                contentStream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                contentStream.newLineAtOffset(100, 700);
                contentStream.showText("Signature spike test document");
                contentStream.endText();
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    public static byte[] sign(byte[] unsignedPdf, TestPki.IssuedIdentity identity) throws IOException {
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName());
    }

    /**
     * Same as {@link #sign(byte[], TestPki.IssuedIdentity)}, but with an
     * arbitrary {@code /SubFilter} name (e.g. an unsupported or unrecognized
     * one). The CMS content itself is unaffected by this value; it only
     * changes what the signature dictionary declares.
     */
    public static byte[] sign(byte[] unsignedPdf, TestPki.IssuedIdentity identity, String subFilter)
            throws IOException {
        return sign(unsignedPdf, identity, subFilter, content -> createDetachedCms(content, identity), 2);
    }

    /**
     * Shared signing boilerplate: builds the signature dictionary, sets up
     * the incremental save, and delegates only the CMS-generation step to
     * {@code cmsBuilder} -- reused by both the plain signing methods above
     * and the timestamp-carrying ones below. {@code sizeMultiplier} scales
     * the reserved {@code /Contents} placeholder ({@link
     * SignatureOptions#DEFAULT_SIGNATURE_SIZE} times this value): a
     * signature carrying an embedded RFC 3161 token (itself another CMS
     * SignedData, with its own certificate chain) needs a larger reservation
     * than a plain one.
     */
    private static byte[] sign(
            byte[] unsignedPdf, TestPki.IssuedIdentity identity, String subFilter, SignatureInterface cmsBuilder,
            int sizeMultiplier) throws IOException {
        try (PDDocument document = org.apache.pdfbox.Loader.loadPDF(unsignedPdf)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(COSName.getPDFName(subFilter));
            signature.setName(identity.endEntityCertificate().getSubjectX500Principal().getName());
            signature.setReason("Signature spike test");
            signature.setSignDate(Calendar.getInstance());

            SignatureOptions signatureOptions = new SignatureOptions();
            signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * sizeMultiplier);

            document.addSignature(signature, cmsBuilder, signatureOptions);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    /**
     * Same as {@link #sign(byte[], TestPki.IssuedIdentity)}, but the CMS
     * signature also carries a genuine RFC 3161 signature timestamp
     * (unsigned attribute {@code id-aa-signatureTimeStampToken}), issued by
     * an in-test TSA over the actual signature value -- the typical
     * approach: sign normally first, then replace the {@code
     * SignerInformation}'s unsigned attributes with the token ({@link
     * SignerInformation#replaceUnsignedAttributes}).
     */
    public static byte[] signWithTimestamp(
            byte[] unsignedPdf, TestPki.IssuedIdentity identity, TestPki.TsaIdentity tsaIdentity) throws IOException {
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(),
                content -> createDetachedCmsWithTimestamp(content, identity, tsaIdentity, false), 8);
    }

    /**
     * Same as {@link #signWithTimestamp}, but the embedded timestamp token's
     * message imprint was computed over unrelated bytes, not the actual
     * signature value: a TSA has no way to know the imprint it is asked to
     * sign is wrong, so the token itself is otherwise perfectly valid --
     * only the imprint comparison against the real signature value fails.
     */
    public static byte[] signWithTamperedTimestamp(
            byte[] unsignedPdf, TestPki.IssuedIdentity identity, TestPki.TsaIdentity tsaIdentity) throws IOException {
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(),
                content -> createDetachedCmsWithTimestamp(content, identity, tsaIdentity, true), 8);
    }

    /** Loads an already-signed PDF and adds a further incremental update (document info change). */
    public static byte[] applyIncrementalUpdate(byte[] signedPdf) throws IOException {
        try (PDDocument document = org.apache.pdfbox.Loader.loadPDF(signedPdf)) {
            document.getDocumentInformation().setTitle("Modified after signing");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    private static byte[] createDetachedCms(InputStream content, TestPki.IssuedIdentity identity)
            throws IOException {
        try {
            byte[] contentBytes = content.readAllBytes();

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            PrivateKey privateKey = identity.endEntityPrivateKey();
            X509Certificate signerCertificate = identity.endEntityCertificate();

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);

            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder()
                                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                    .build())
                            .build(contentSigner, signerCertificate));

            List<X509Certificate> chain = identity.chain();
            generator.addCertificates(new JcaCertStore(chain));

            CMSTypedData cmsData = new CMSProcessableByteArray(contentBytes);
            CMSSignedData signedData = generator.generate(cmsData, false);

            return signedData.getEncoded();
        } catch (CMSException | OperatorCreationException | CertificateEncodingException e) {
            throw new IOException("Failed to build detached CMS signature", e);
        }
    }

    /**
     * Same as {@link #createDetachedCms}, but afterwards issues a genuine
     * RFC 3161 timestamp token from {@code tsaIdentity} and embeds it as the
     * signer's unsigned {@code id-aa-signatureTimeStampToken} attribute
     * ({@link SignerInformation#replaceUnsignedAttributes}). When {@code
     * tamperImprint} is {@code true}, the token is requested over unrelated
     * bytes instead of the real signature value, simulating a timestamp
     * whose message imprint does not match what it claims to seal.
     */
    private static byte[] createDetachedCmsWithTimestamp(
            InputStream content, TestPki.IssuedIdentity identity, TestPki.TsaIdentity tsaIdentity,
            boolean tamperImprint) throws IOException {
        try {
            byte[] contentBytes = content.readAllBytes();

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            PrivateKey privateKey = identity.endEntityPrivateKey();
            X509Certificate signerCertificate = identity.endEntityCertificate();

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);

            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder()
                                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                    .build())
                            .build(contentSigner, signerCertificate));

            generator.addCertificates(new JcaCertStore(identity.chain()));

            CMSTypedData cmsData = new CMSProcessableByteArray(contentBytes);
            CMSSignedData signedData = generator.generate(cmsData, false);

            SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();
            byte[] imprintSource = tamperImprint
                    ? "this is not the real signature value".getBytes(java.nio.charset.StandardCharsets.UTF_8)
                    : signerInformation.getSignature();

            TimeStampToken token = issueTimeStampToken(imprintSource, tsaIdentity);

            AttributeTable existingUnsignedAttributes = signerInformation.getUnsignedAttributes();
            Hashtable<ASN1ObjectIdentifier, Attribute> unsignedAttributeTable =
                    existingUnsignedAttributes == null ? new Hashtable<>() : existingUnsignedAttributes.toHashtable();
            AttributeTable newUnsignedAttributes = new AttributeTable(unsignedAttributeTable)
                    .add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, token.toCMSSignedData().toASN1Structure());

            SignerInformation timestampedSignerInformation =
                    SignerInformation.replaceUnsignedAttributes(signerInformation, newUnsignedAttributes);
            CMSSignedData timestampedSignedData = CMSSignedData.replaceSigners(
                    signedData, new SignerInformationStore(timestampedSignerInformation));

            return timestampedSignedData.getEncoded();
        } catch (CMSException | OperatorCreationException | CertificateEncodingException | TSPException e) {
            throw new IOException("Failed to build detached CMS signature with a timestamp", e);
        }
    }

    /** Issues a genuine RFC 3161 timestamp token over the SHA-256 digest of {@code imprintSource}. */
    private static TimeStampToken issueTimeStampToken(byte[] imprintSource, TestPki.TsaIdentity tsaIdentity)
            throws IOException, OperatorCreationException, CMSException, TSPException, CertificateEncodingException {
        byte[] imprint;
        try {
            imprint = MessageDigest.getInstance("SHA-256").digest(imprintSource);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is unavailable", e);
        }

        TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
        // RFC 3161: a TSA only embeds its certificate in the response when
        // the request's certReq flag asks for it.
        requestGenerator.setCertReq(true);
        TimeStampRequest request = requestGenerator.generate(TSPAlgorithms.SHA256, imprint);

        DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build()
                .get(new AlgorithmIdentifier(TSPAlgorithms.SHA256));

        ContentSigner tsaSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(tsaIdentity.privateKey());

        org.bouncycastle.cms.SignerInfoGenerator tsaSignerInfoGenerator = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
                .build(tsaSigner, tsaIdentity.certificate());

        TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(
                tsaSignerInfoGenerator, digestCalculator, new ASN1ObjectIdentifier("1.2.3.4.1"));
        tokenGenerator.addCertificates(new JcaCertStore(tsaIdentity.chain()));

        return tokenGenerator.generate(request, BigInteger.valueOf(System.currentTimeMillis()), new Date());
    }
}
