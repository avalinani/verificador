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
        return sign(unsignedPdf, identity, subFilter, cmsBuilder, sizeMultiplier, Calendar.getInstance());
    }

    private static byte[] sign(
            byte[] unsignedPdf, TestPki.IssuedIdentity identity, String subFilter, SignatureInterface cmsBuilder,
            int sizeMultiplier, Calendar claimedSigningTime) throws IOException {
        try (PDDocument document = org.apache.pdfbox.Loader.loadPDF(unsignedPdf)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(COSName.getPDFName(subFilter));
            signature.setName(identity.endEntityCertificate().getSubjectX500Principal().getName());
            signature.setReason("Signature spike test");
            signature.setSignDate(claimedSigningTime);

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
     * Same as {@link #signWithTimestamp(byte[], TestPki.IssuedIdentity, TestPki.TsaIdentity)}, but the TSA
     * stamps {@code genTime} instead of "now" -- what a forger with any TSA of
     * their own can do, and what a genuine TSA did if the signature is old.
     */
    public static byte[] signWithTimestamp(
            byte[] unsignedPdf, TestPki.IssuedIdentity identity, TestPki.TsaIdentity tsaIdentity,
            java.time.Instant genTime) throws IOException {
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(),
                content -> createDetachedCmsWithTimestamp(content, identity, tsaIdentity, false, Date.from(genTime)), 8);
    }

    /**
     * Same as {@link #sign(byte[], TestPki.IssuedIdentity)}, but the signature
     * dictionary claims {@code claimedSigningTime} as the signing time
     * ({@code /M}) instead of "now" -- the signer-declared date the validator
     * must never trust.
     */
    public static byte[] signClaimingTime(
            byte[] unsignedPdf, TestPki.IssuedIdentity identity, java.time.Instant claimedSigningTime)
            throws IOException {
        Calendar claimed = Calendar.getInstance();
        claimed.setTimeInMillis(claimedSigningTime.toEpochMilli());
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(),
                content -> createDetachedCms(content, identity), 2, claimed);
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

    /**
     * Same as {@link #sign(byte[], TestPki.IssuedIdentity)}, but reproduces
     * the exact real-world structure found in a genuinely non-standard
     * signed PDF (T09c, verified by disassembling the actual CMS bytes of a
     * real file): a legacy-style CMS with <em>no signed attributes at all</em>
     * (so the signature is computed directly over the signed content, per
     * RFC 5652 -- no {@code messageDigest}, no {@code signingTime}), a bare
     * {@code rsaEncryption} OID ({@code 1.2.840.113549.1.1.1}, no digest
     * implied) as {@code digestEncryptionAlgorithm}, and the SIGNATURE
     * algorithm's OID ({@code sha256WithRSAEncryption}, {@code
     * 1.2.840.113549.1.1.11}) where the plain digest OID ({@code
     * id-sha256}) belongs, as {@code digestAlgorithm}. Adobe accepts this
     * encoding; Bouncy Castle's own digest-calculator lookup rejects it
     * with {@code NoSuchAlgorithmException} unless normalized first, and
     * (a separate, deeper issue found only by testing against the real
     * file) its own {@code SignerInformation#verify} cannot correctly
     * verify this exact combination even after normalizing the digest
     * calculator -- see {@code CmsSignatureVerification}'s Javadoc.
     *
     * <p>Built entirely by hand (not via {@link CMSSignedDataGenerator},
     * which always adds signed attributes): the signature itself is a
     * plain {@code Signature.getInstance("SHA256withRSA")} over the raw
     * content bytes, exactly what a real tool producing this structure
     * would compute.
     */
    public static byte[] signWithSignatureAlgorithmOidAsDigestOid(byte[] unsignedPdf, TestPki.IssuedIdentity identity)
            throws IOException {
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(),
                content -> createDetachedCmsWithSignatureAlgorithmOidAsDigestOid(content, identity), 2);
    }

    /**
     * T09d follow-up: same mislabeled-{@code digestAlgorithm} bug as {@link
     * #signWithSignatureAlgorithmOidAsDigestOid}, but with signed attributes
     * present ({@code contentType} + {@code messageDigest}) -- exercising
     * {@code CmsSignatureVerification#verifyWithMislabeledDigestAlgorithm}'s
     * other branch (checking the {@code messageDigest} attribute, then
     * verifying over the signed attributes' DER encoding, rather than over
     * the raw content directly). Per RFC 5652 5.4, the signature is computed
     * over the DER encoding of the signed-attributes {@code SET OF}
     * structure (re-tagged from the {@code [0] IMPLICIT} form used inside
     * {@code SignerInfo} itself back to its universal {@code SET} tag) --
     * exactly what {@link AttributeTable#toASN1Structure()} reproduces on
     * the verifying side.
     */
    public static byte[] signWithSignatureAlgorithmOidAsDigestOidAndSignedAttributes(
            byte[] unsignedPdf, TestPki.IssuedIdentity identity) throws IOException {
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(),
                content -> createDetachedCmsWithSignatureAlgorithmOidAsDigestOidAndSignedAttributes(content, identity),
                2);
    }

    private static byte[] createDetachedCmsWithSignatureAlgorithmOidAsDigestOid(
            InputStream content, TestPki.IssuedIdentity identity) throws IOException {
        try {
            byte[] contentBytes = content.readAllBytes();

            // The signature itself: a standard "hash then RSA-encrypt"
            // operation over the raw content, exactly what a real signer
            // would produce for a CMS with no signed attributes.
            java.security.Signature rsaSignature =
                    java.security.Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            rsaSignature.initSign(identity.endEntityPrivateKey());
            rsaSignature.update(contentBytes);
            byte[] encryptedDigest = rsaSignature.sign();

            // The bug: digestAlgorithm carries the SIGNATURE algorithm's
            // OID (a complete, valid algorithm on its own -- just in the
            // wrong field), while digestEncryptionAlgorithm carries only
            // the bare, under-specified rsaEncryption OID -- exactly the
            // combination found in the real file this fixture reproduces.
            AlgorithmIdentifier signatureOidAsDigestAlgorithm = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption, org.bouncycastle.asn1.DERNull.INSTANCE);
            AlgorithmIdentifier bareRsaEncryption =
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, org.bouncycastle.asn1.DERNull.INSTANCE);

            org.bouncycastle.cert.X509CertificateHolder signerHolder =
                    new org.bouncycastle.cert.X509CertificateHolder(identity.endEntityCertificate().getEncoded());
            org.bouncycastle.asn1.cms.SignerIdentifier sid = new org.bouncycastle.asn1.cms.SignerIdentifier(
                    new org.bouncycastle.asn1.cms.IssuerAndSerialNumber(
                            signerHolder.getIssuer(), signerHolder.getSerialNumber()));

            // No signed attributes (null): the real file this reproduces
            // has none either -- a legacy-style detached PKCS#7 signature.
            org.bouncycastle.asn1.cms.SignerInfo signerInfo = new org.bouncycastle.asn1.cms.SignerInfo(
                    sid,
                    signatureOidAsDigestAlgorithm,
                    (org.bouncycastle.asn1.ASN1Set) null,
                    bareRsaEncryption,
                    new org.bouncycastle.asn1.DEROctetString(encryptedDigest),
                    (org.bouncycastle.asn1.ASN1Set) null);

            org.bouncycastle.asn1.ASN1EncodableVector signerInfosVector = new org.bouncycastle.asn1.ASN1EncodableVector();
            signerInfosVector.add(signerInfo);

            org.bouncycastle.asn1.ASN1EncodableVector digestAlgorithmsVector = new org.bouncycastle.asn1.ASN1EncodableVector();
            digestAlgorithmsVector.add(signatureOidAsDigestAlgorithm);

            org.bouncycastle.asn1.cms.ContentInfo encapContentInfo =
                    new org.bouncycastle.asn1.cms.ContentInfo(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.data, null);

            org.bouncycastle.asn1.ASN1Set certificates = new org.bouncycastle.asn1.DERSet(
                    identity.chain().stream()
                            .map(cert -> {
                                try {
                                    return new org.bouncycastle.cert.X509CertificateHolder(cert.getEncoded())
                                            .toASN1Structure();
                                } catch (java.security.cert.CertificateEncodingException | IOException e) {
                                    throw new IllegalStateException(e);
                                }
                            })
                            .toArray(org.bouncycastle.asn1.ASN1Encodable[]::new));

            org.bouncycastle.asn1.cms.SignedData signedData = new org.bouncycastle.asn1.cms.SignedData(
                    new org.bouncycastle.asn1.DERSet(digestAlgorithmsVector),
                    encapContentInfo,
                    certificates,
                    null,
                    new org.bouncycastle.asn1.DERSet(signerInfosVector));

            org.bouncycastle.asn1.cms.ContentInfo contentInfo =
                    new org.bouncycastle.asn1.cms.ContentInfo(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.signedData, signedData);
            return contentInfo.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        } catch (java.security.GeneralSecurityException | IOException e) {
            throw new IOException("Failed to build a CMS signature with a non-standard digestAlgorithm OID", e);
        }
    }

    /**
     * Same idea as {@link #createDetachedCmsWithSignatureAlgorithmOidAsDigestOid},
     * but with a real signed-attributes set ({@code contentType} +
     * {@code messageDigest}, computed with the actual SHA-256 digest -- a
     * genuine signer always hashes correctly even when it mislabels the
     * algorithm identifier field): the signature is computed over the
     * signed attributes' DER encoding, not the raw content directly.
     */
    private static byte[] createDetachedCmsWithSignatureAlgorithmOidAsDigestOidAndSignedAttributes(
            InputStream content, TestPki.IssuedIdentity identity) throws IOException {
        try {
            byte[] contentBytes = content.readAllBytes();
            byte[] contentDigest = MessageDigest.getInstance("SHA-256").digest(contentBytes);

            org.bouncycastle.asn1.cms.Attribute contentTypeAttribute = new org.bouncycastle.asn1.cms.Attribute(
                    org.bouncycastle.asn1.cms.CMSAttributes.contentType,
                    new org.bouncycastle.asn1.DERSet(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.data));
            org.bouncycastle.asn1.cms.Attribute messageDigestAttribute = new org.bouncycastle.asn1.cms.Attribute(
                    org.bouncycastle.asn1.cms.CMSAttributes.messageDigest,
                    new org.bouncycastle.asn1.DERSet(new org.bouncycastle.asn1.DEROctetString(contentDigest)));
            org.bouncycastle.asn1.ASN1EncodableVector signedAttrsVector = new org.bouncycastle.asn1.ASN1EncodableVector();
            signedAttrsVector.add(contentTypeAttribute);
            signedAttrsVector.add(messageDigestAttribute);
            org.bouncycastle.asn1.ASN1Set signedAttributes = new org.bouncycastle.asn1.DERSet(signedAttrsVector);

            // RFC 5652 5.4: the signature covers the DER encoding of the
            // signed attributes as a plain SET OF (universal tag), not the
            // [0] IMPLICIT form SignerInfo itself uses to carry it.
            byte[] signedAttributesDer = signedAttributes.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
            java.security.Signature rsaSignature =
                    java.security.Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            rsaSignature.initSign(identity.endEntityPrivateKey());
            rsaSignature.update(signedAttributesDer);
            byte[] encryptedDigest = rsaSignature.sign();

            AlgorithmIdentifier signatureOidAsDigestAlgorithm = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption, org.bouncycastle.asn1.DERNull.INSTANCE);
            AlgorithmIdentifier bareRsaEncryption =
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, org.bouncycastle.asn1.DERNull.INSTANCE);

            org.bouncycastle.cert.X509CertificateHolder signerHolder =
                    new org.bouncycastle.cert.X509CertificateHolder(identity.endEntityCertificate().getEncoded());
            org.bouncycastle.asn1.cms.SignerIdentifier sid = new org.bouncycastle.asn1.cms.SignerIdentifier(
                    new org.bouncycastle.asn1.cms.IssuerAndSerialNumber(
                            signerHolder.getIssuer(), signerHolder.getSerialNumber()));

            org.bouncycastle.asn1.cms.SignerInfo signerInfo = new org.bouncycastle.asn1.cms.SignerInfo(
                    sid,
                    signatureOidAsDigestAlgorithm,
                    signedAttributes,
                    bareRsaEncryption,
                    new org.bouncycastle.asn1.DEROctetString(encryptedDigest),
                    (org.bouncycastle.asn1.ASN1Set) null);

            org.bouncycastle.asn1.ASN1EncodableVector signerInfosVector = new org.bouncycastle.asn1.ASN1EncodableVector();
            signerInfosVector.add(signerInfo);

            org.bouncycastle.asn1.ASN1EncodableVector digestAlgorithmsVector = new org.bouncycastle.asn1.ASN1EncodableVector();
            digestAlgorithmsVector.add(signatureOidAsDigestAlgorithm);

            org.bouncycastle.asn1.cms.ContentInfo encapContentInfo =
                    new org.bouncycastle.asn1.cms.ContentInfo(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.data, null);

            org.bouncycastle.asn1.ASN1Set certificates = new org.bouncycastle.asn1.DERSet(
                    identity.chain().stream()
                            .map(cert -> {
                                try {
                                    return new org.bouncycastle.cert.X509CertificateHolder(cert.getEncoded())
                                            .toASN1Structure();
                                } catch (java.security.cert.CertificateEncodingException | IOException e) {
                                    throw new IllegalStateException(e);
                                }
                            })
                            .toArray(org.bouncycastle.asn1.ASN1Encodable[]::new));

            org.bouncycastle.asn1.cms.SignedData signedData = new org.bouncycastle.asn1.cms.SignedData(
                    new org.bouncycastle.asn1.DERSet(digestAlgorithmsVector),
                    encapContentInfo,
                    certificates,
                    null,
                    new org.bouncycastle.asn1.DERSet(signerInfosVector));

            org.bouncycastle.asn1.cms.ContentInfo contentInfo =
                    new org.bouncycastle.asn1.cms.ContentInfo(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.signedData, signedData);
            return contentInfo.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        } catch (java.security.GeneralSecurityException | IOException e) {
            throw new IOException(
                    "Failed to build a CMS signature with a non-standard digestAlgorithm OID and signed attributes",
                    e);
        }
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
        return createDetachedCmsWithTimestamp(content, identity, tsaIdentity, tamperImprint, new Date());
    }

    private static byte[] createDetachedCmsWithTimestamp(
            InputStream content, TestPki.IssuedIdentity identity, TestPki.TsaIdentity tsaIdentity,
            boolean tamperImprint, Date genTime) throws IOException {
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

            TimeStampToken token = issueTimeStampToken(imprintSource, tsaIdentity, genTime);

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
    private static TimeStampToken issueTimeStampToken(
            byte[] imprintSource, TestPki.TsaIdentity tsaIdentity, Date genTime)
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

        return tokenGenerator.generate(request, BigInteger.valueOf(System.currentTimeMillis()), genTime);
    }
}
