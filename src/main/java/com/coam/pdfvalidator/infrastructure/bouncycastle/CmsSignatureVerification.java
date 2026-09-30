package com.coam.pdfvalidator.infrastructure.bouncycastle;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import com.coam.pdfvalidator.domain.model.TimestampInfo;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;

/**
 * Parses a detached CMS/PKCS#7 signature (as embedded in a PDF's {@code
 * /Contents}) and verifies it against the actual signed bytes: this
 * verifies both that the signed message digest matches the ByteRange-covered
 * bytes (tamper detection) and that the signature itself validates against
 * the embedded signer certificate.
 *
 * <p>Promotes the approach already proven in {@code
 * spike.SpikeSignatureChecker} (see its Javadoc for why {@code
 * ASN1InputStream#readObject()} is required rather than {@code
 * CMSSignedData(byte[])}: PDFBox's {@code /Contents} placeholder is
 * zero-padded to its reserved size).
 *
 * <h2>Integrity is independent of certificate validity (T09c)</h2>
 * The signer's certificate is verified with its bare {@link
 * java.security.PublicKey} (built via {@link JcaContentVerifierProviderBuilder#build(java.security.PublicKey)}),
 * never with the {@link X509CertificateHolder} overload: Bouncy Castle's own
 * {@code SignerInformation#verify} additionally checks the certificate's own
 * validity against the CMS {@code signingTime} attribute when it is built
 * from a certificate, throwing {@code CMSVerifierCertificateNotValidException}
 * when the signer certificate had already expired (a real, observed case:
 * a Spanish qualified signature made a few months after its own signer
 * certificate's {@code notAfter}) -- but cryptographic integrity (did the
 * bytes match what was actually signed?) and certificate validity (was the
 * signer allowed to sign at that time?) are two independently reportable
 * facts, not one. This class verifies only the former; the latter is
 * reported separately, as {@link Result#anomaly()} here (a note about the
 * certificate's own validity window) and via the certificate chain's {@code
 * EXPIRED} status once the use case validates it at the claimed signing
 * time.
 *
 * <h2>Non-standard digestAlgorithm encoding (T09c)</h2>
 * Some real-world signing tools encode a {@code SignerInfo}'s {@code
 * digestAlgorithm} field using the SIGNATURE algorithm's OID (e.g. {@code
 * sha256WithRSAEncryption}) instead of the plain digest OID -- Adobe accepts
 * it, Bouncy Castle's default digest lookup does not. The {@link
 * DigestCalculatorProvider} used to verify the signature is wrapped in a
 * {@link NormalizingDigestCalculatorProvider} that maps such an OID to its
 * real digest before delegating; when normalization was actually needed,
 * that fact is also surfaced via {@link Result#anomaly()}.
 */
final class CmsSignatureVerification {

    private static final System.Logger LOG = System.getLogger(CmsSignatureVerification.class.getName());

    /**
     * @param valid              whether the CMS signature verified: the
     *                           signed {@code messageDigest} matches the
     *                           ByteRange-covered bytes and the signature
     *                           value itself is valid for the signer's
     *                           public key -- independent of whether the
     *                           signer's certificate was valid at the
     *                           declared signing time
     * @param signerCertificate  the signer's certificate, or {@code null}
     *                           when it could not be identified
     * @param certificateChain   every certificate found in the CMS,
     *                           ordered signer first, then issuer, then
     *                           that issuer's issuer, and so on when the
     *                           chain can be followed; empty only when the
     *                           CMS itself could not be parsed at all
     * @param timestamp          the RFC 3161 signature timestamp attached
     *                           to this signer, or {@link
     *                           TimestampInfo#absent()} when there is none
     * @param reason             a human-readable, non-sensitive explanation
     *                           of why {@code valid} is {@code false};
     *                           {@code null} when {@code valid} is {@code true}
     * @param anomaly            a diagnostic note that does not by itself
     *                           mean the signature is invalid (e.g. the
     *                           signer certificate was not valid at the
     *                           declared signing time, or the CMS encoded a
     *                           non-standard digest algorithm OID), or
     *                           {@code null} when there is none
     */
    record Result(
            boolean valid,
            X509Certificate signerCertificate,
            List<X509Certificate> certificateChain,
            TimestampInfo timestamp,
            String reason,
            String anomaly) {

        static Result unparseable(String reason) {
            return new Result(false, null, List.of(), TimestampInfo.absent(), Objects.requireNonNull(reason), null);
        }
    }

    private CmsSignatureVerification() {
    }

    static Result verify(byte[] signedBytes, byte[] cmsDer, Provider bcProvider) {
        return verify(signedBytes, cmsDer, bcProvider, SignatureLimits.DEFAULT);
    }

    static Result verify(byte[] signedBytes, byte[] cmsDer, Provider bcProvider, SignatureLimits limits) {
        CMSSignedData signedData;
        try {
            ContentInfo contentInfo = readContentInfo(cmsDer);
            signedData = new CMSSignedData(new CMSProcessableByteArray(signedBytes), contentInfo);
        } catch (CMSException | IOException | RuntimeException e) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to parse a CMS signature", e);
            return Result.unparseable("CMS container could not be parsed");
        }

        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            return Result.unparseable("CMS container could not be parsed: no signer information present");
        }
        SignerInformation signerInformation = signers.iterator().next();

        Store<X509CertificateHolder> certificateStore = signedData.getCertificates();
        Collection<X509CertificateHolder> matches = certificateStore.getMatches(signerInformation.getSID());
        if (matches.isEmpty()) {
            return Result.unparseable("CMS container could not be parsed: signer certificate not found");
        }
        X509CertificateHolder signerHolder = matches.iterator().next();

        X509Certificate signerCertificate;
        List<X509Certificate> chain;
        String truncationNote = null;
        try {
            signerCertificate = toJavaCertificate(signerHolder, bcProvider);
            // T20: at most maxCertificatesPerSignature certificates are converted and ordered -- the signer
            // first, then the others in container order -- so a CMS stuffed with certificates costs a bounded
            // amount of work. Dropping one can only make the chain incomplete (fail closed), never trusted.
            List<X509Certificate> allCertificates = new ArrayList<>();
            allCertificates.add(signerCertificate);
            int total = 0;
            for (X509CertificateHolder holder : certificateStore.getMatches(null)) {
                total++;
                if (allCertificates.size() < limits.maxCertificatesPerSignature() && !holder.equals(signerHolder)) {
                    allCertificates.add(toJavaCertificate(holder, bcProvider));
                }
            }
            if (total > limits.maxCertificatesPerSignature()) {
                truncationNote = "signature carries " + total + " certificates; only "
                        + limits.maxCertificatesPerSignature() + " were considered, the chain may be incomplete";
            }
            chain = orderSignerFirst(signerCertificate, allCertificates, limits.maxChainLength());
        } catch (CertificateException | RuntimeException e) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to map certificates extracted from a CMS signature", e);
            return Result.unparseable("CMS container could not be parsed: certificate data unreadable");
        }

        TimestampInfo timestamp = SignatureTimestampVerifier.verify(signerInformation, bcProvider);
        String certificateValidityNote = certificateValidityAtSigningTimeNote(signerInformation, signerCertificate);
        boolean digestOidMislabeled = DigestAlgorithmOidNormalizer.isSignatureAlgorithmOid(
                signerInformation.getDigestAlgorithmID().getAlgorithm());
        String digestOidNote = digestOidMislabeled
                ? "non-standard digestAlgorithm encoding (signature algorithm OID used instead of a digest OID)"
                : null;
        String anomaly = combineNotes(combineNotes(certificateValidityNote, digestOidNote), truncationNote);

        boolean valid;
        String reason = null;
        try {
            // A mislabeled digestAlgorithm needs its own verification path
            // -- see verifyWithMislabeledDigestAlgorithm's Javadoc for why
            // Bouncy Castle's own SignerInformation#verify cannot be
            // trusted for this case.
            valid = digestOidMislabeled
                    ? verifyWithMislabeledDigestAlgorithm(signerInformation, signedBytes, signerCertificate, bcProvider)
                    : signerInformation.verify(buildVerifier(signerCertificate, bcProvider));
            if (!valid) {
                reason = "signature value does not verify";
            }
        } catch (CMSSignerDigestMismatchException e) {
            valid = false;
            reason = "messageDigest does not match the signed bytes";
        } catch (CMSException e) {
            valid = false;
            reason = "signature value does not verify";
            LOG.log(System.Logger.Level.DEBUG, "CMS signature verification failed", e);
        } catch (OperatorCreationException | IOException | RuntimeException e) {
            valid = false;
            reason = "signature could not be verified";
            LOG.log(System.Logger.Level.DEBUG, "Unexpected error verifying a CMS signature", e);
        }

        return new Result(valid, signerCertificate, chain, timestamp, reason, anomaly);
    }

    /**
     * Verifies a signature whose {@code digestAlgorithm} field is itself a
     * complete signature algorithm OID (see {@link
     * DigestAlgorithmOidNormalizer}), bypassing {@link
     * SignerInformation#verify} entirely.
     *
     * <p><b>Why this bypass is necessary</b>: disassembling {@code
     * SignerInformation#doVerify} (Bouncy Castle 1.86, {@code
     * bcpkix-jdk18on}) shows that for a CMS with <em>no signed
     * attributes</em> and an RSA signature, it reconstructs the PKCS#1
     * {@code DigestInfo} it expects to find inside the signature directly
     * from the (here, mislabeled) {@code digestAlgorithm} field, via a
     * private {@code translateBrokenRSAPkcs7} helper that only
     * special-cases the historical SHA-1 variant of exactly this bug
     * (a bare {@code rsaEncryption} signature OID paired with {@code
     * sha1WithRSA}/{@code sha1WithRSAEncryption} mistakenly used as the
     * digest OID) -- never the SHA-224/256/384/512 variants. For any of
     * those, the reconstructed {@code DigestInfo} embeds the wrong
     * algorithm OID and can never match the real signature, so {@code
     * verify()} returns {@code false} for a signature that is otherwise
     * entirely valid (confirmed against a real signed PDF, T09c).
     *
     * <p>Since the mislabeled OID is itself a complete, valid signature
     * algorithm identifier (e.g. {@code sha256WithRSAEncryption} really
     * does mean "SHA-256 then RSA"), it is used directly here to build a
     * {@link ContentVerifier}, sidestepping Bouncy Castle's internal
     * (buggy, for this one case) algorithm-combination logic altogether.
     * This also covers the case where signed attributes <em>are</em>
     * present (verifying over their DER encoding, after independently
     * checking the {@code messageDigest} attribute) exactly as {@link
     * SignerInformation#verify} would, just without relying on its
     * internal combination logic for the signature step.
     *
     * @throws CMSSignerDigestMismatchException if a signed {@code
     *                                          messageDigest} attribute is
     *                                          present but does not match
     *                                          the actual digest of {@code
     *                                          signedBytes}
     */
    private static boolean verifyWithMislabeledDigestAlgorithm(
            SignerInformation signerInformation, byte[] signedBytes, X509Certificate signerCertificate,
            Provider bcProvider) throws OperatorCreationException, IOException, CMSException {
        AlgorithmIdentifier completeSignatureAlgorithm = signerInformation.getDigestAlgorithmID();

        byte[] verifiedBytes;
        AttributeTable signedAttributes = signerInformation.getSignedAttributes();
        if (signedAttributes != null) {
            AlgorithmIdentifier normalizedDigestAlgorithm =
                    DigestAlgorithmOidNormalizer.normalize(completeSignatureAlgorithm);
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(bcProvider).build().get(normalizedDigestAlgorithm);
            try (OutputStream digestOut = digestCalculator.getOutputStream()) {
                digestOut.write(signedBytes);
            }
            byte[] actualDigest = digestCalculator.getDigest();
            byte[] claimedDigest = messageDigestAttributeValue(signedAttributes);
            if (claimedDigest == null || !java.util.Arrays.equals(actualDigest, claimedDigest)) {
                throw new CMSSignerDigestMismatchException(
                        "message-digest attribute value does not match calculated value");
            }
            verifiedBytes = signedAttributes.toASN1Structure().getEncoded(ASN1Encoding.DER);
        } else {
            verifiedBytes = signedBytes;
        }

        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider(bcProvider)
                .build(signerCertificate.getPublicKey());
        ContentVerifier contentVerifier = contentVerifierProvider.get(completeSignatureAlgorithm);
        try (OutputStream sigOut = contentVerifier.getOutputStream()) {
            sigOut.write(verifiedBytes);
        }
        return contentVerifier.verify(signerInformation.getSignature());
    }

    private static byte[] messageDigestAttributeValue(AttributeTable signedAttributes) {
        Attribute attribute = signedAttributes.get(CMSAttributes.messageDigest);
        if (attribute == null) {
            return null;
        }
        return ASN1OctetString.getInstance(attribute.getAttrValues().getObjectAt(0)).getOctets();
    }

    /**
     * Builds a {@link SignerInformationVerifier} directly from the signer's
     * bare public key (never from the {@link X509CertificateHolder}
     * overload) so that {@link SignerInformationVerifier#hasAssociatedCertificate()}
     * is {@code false} and Bouncy Castle never performs its own
     * certificate-validity-at-signingTime check -- see the class Javadoc.
     * The {@link DigestCalculatorProvider} is wrapped to tolerate a
     * non-standard signature-algorithm OID used as the digest OID -- also
     * see the class Javadoc.
     */
    private static SignerInformationVerifier buildVerifier(X509Certificate signerCertificate, Provider bcProvider)
            throws OperatorCreationException {
        DigestCalculatorProvider digestCalculatorProvider = new NormalizingDigestCalculatorProvider(
                new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build());
        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider(bcProvider)
                .build(signerCertificate.getPublicKey());
        return new SignerInformationVerifier(
                new DefaultCMSSignatureAlgorithmNameGenerator(),
                new DefaultSignatureAlgorithmIdentifierFinder(),
                contentVerifierProvider,
                digestCalculatorProvider);
    }

    /**
     * Independently checks whether {@code signerCertificate} was valid at
     * the CMS {@code signingTime} signed attribute (when present), returning
     * a human-readable note when it was not -- {@code null} otherwise (no
     * {@code signingTime} attribute at all, or the certificate was valid).
     * This is deliberately separate from the crypto verification above: a
     * certificate that had already expired when it signed does not, by
     * itself, mean the bytes were tampered with.
     */
    private static String certificateValidityAtSigningTimeNote(
            SignerInformation signerInformation, X509Certificate signerCertificate) {
        Instant signingTime = signingTimeAttribute(signerInformation);
        if (signingTime == null) {
            return null;
        }
        try {
            signerCertificate.checkValidity(Date.from(signingTime));
            return null;
        } catch (CertificateExpiredException e) {
            return "signer certificate was not valid at the declared signing time (notAfter "
                    + signerCertificate.getNotAfter().toInstant() + ", signed " + signingTime + ")";
        } catch (CertificateNotYetValidException e) {
            return "signer certificate was not valid at the declared signing time (notBefore "
                    + signerCertificate.getNotBefore().toInstant() + ", signed " + signingTime + ")";
        }
    }

    private static Instant signingTimeAttribute(SignerInformation signerInformation) {
        AttributeTable signedAttributes = signerInformation.getSignedAttributes();
        if (signedAttributes == null) {
            return null;
        }
        Attribute attribute = signedAttributes.get(CMSAttributes.signingTime);
        if (attribute == null) {
            return null;
        }
        try {
            Time time = Time.getInstance(attribute.getAttrValues().getObjectAt(0).toASN1Primitive());
            return time.getDate().toInstant();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String combineNotes(String a, String b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a + "; " + b;
    }

    private static ContentInfo readContentInfo(byte[] cmsDer) throws IOException {
        try (ASN1InputStream asn1In = new ASN1InputStream(cmsDer)) {
            ASN1Primitive object = asn1In.readObject();
            return ContentInfo.getInstance(object);
        }
    }

    private static X509Certificate toJavaCertificate(X509CertificateHolder holder, Provider bcProvider)
            throws CertificateException {
        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(holder);
    }

    /**
     * Orders {@code certificates} starting with {@code signer}, followed by
     * its issuer (matched by subject/issuer distinguished name), then that
     * issuer's issuer, and so on until a self-signed (root) certificate is
     * reached or no further issuer can be found. Any leftover, unrelated
     * certificates are appended at the end rather than dropped.
     */
    static List<X509Certificate> orderSignerFirst(
            X509Certificate signer, List<X509Certificate> certificates, int maxChainLength) {
        if (signer == null) {
            return List.copyOf(certificates);
        }
        List<X509Certificate> remaining = new ArrayList<>(certificates);
        removeByEncodedValue(remaining, signer);

        List<X509Certificate> ordered = new ArrayList<>();
        ordered.add(signer);

        X509Certificate current = signer;
        while (ordered.size() < maxChainLength) {
            X500Principal issuerDn = current.getIssuerX500Principal();
            if (issuerDn.equals(current.getSubjectX500Principal())) {
                break; // self-signed: reached the root
            }
            X509Certificate issuer = findBySubject(remaining, issuerDn);
            if (issuer == null) {
                break; // issuer not present in this CMS
            }
            ordered.add(issuer);
            removeByEncodedValue(remaining, issuer);
            current = issuer;
        }
        ordered.addAll(remaining);
        return List.copyOf(ordered);
    }

    private static X509Certificate findBySubject(List<X509Certificate> certificates, X500Principal subjectDn) {
        for (X509Certificate certificate : certificates) {
            if (certificate.getSubjectX500Principal().equals(subjectDn)) {
                return certificate;
            }
        }
        return null;
    }

    private static void removeByEncodedValue(List<X509Certificate> certificates, X509Certificate toRemove) {
        certificates.removeIf(candidate -> certificatesMatch(candidate, toRemove));
    }

    private static boolean certificatesMatch(X509Certificate a, X509Certificate b) {
        try {
            return java.util.Arrays.equals(a.getEncoded(), b.getEncoded());
        } catch (CertificateEncodingException e) {
            return false;
        }
    }
}
