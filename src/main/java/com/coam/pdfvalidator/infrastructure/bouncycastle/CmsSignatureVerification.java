package com.coam.pdfvalidator.infrastructure.bouncycastle;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
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
 */
final class CmsSignatureVerification {

    /**
     * @param valid              whether the CMS signature verified (digest
     *                           matches and the signature itself is valid)
     * @param signerCertificate  the signer's certificate, or {@code null}
     *                           when it could not be identified
     * @param certificateChain   every certificate found in the CMS,
     *                           ordered signer first, then issuer, then
     *                           that issuer's issuer, and so on when the
     *                           chain can be followed; empty when no
     *                           signer certificate could be identified
     */
    record Result(boolean valid, X509Certificate signerCertificate, List<X509Certificate> certificateChain) {

        static Result invalid() {
            return new Result(false, null, List.of());
        }
    }

    private CmsSignatureVerification() {
    }

    static Result verify(byte[] signedBytes, byte[] cmsDer, Provider bcProvider) {
        try {
            ContentInfo contentInfo = readContentInfo(cmsDer);
            CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(signedBytes), contentInfo);
            Store<X509CertificateHolder> certificateStore = signedData.getCertificates();

            Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
            if (signers.isEmpty()) {
                return Result.invalid();
            }
            SignerInformation signerInformation = signers.iterator().next();

            Collection<X509CertificateHolder> matches = certificateStore.getMatches(signerInformation.getSID());
            if (matches.isEmpty()) {
                return Result.invalid();
            }
            X509CertificateHolder signerHolder = matches.iterator().next();

            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(bcProvider)
                    .build(signerHolder);
            // Verifies both that the signed messageDigest attribute matches
            // the actual digest of signedBytes (throws CMSException,
            // including CMSSignerDigestMismatchException, on tampering) and
            // that the signature itself is valid for the signer certificate.
            boolean valid = signerInformation.verify(verifier);

            X509Certificate signerCertificate = toJavaCertificate(signerHolder, bcProvider);
            List<X509Certificate> allCertificates = new ArrayList<>();
            for (X509CertificateHolder holder : certificateStore.getMatches(null)) {
                allCertificates.add(toJavaCertificate(holder, bcProvider));
            }
            List<X509Certificate> chain = orderSignerFirst(signerCertificate, allCertificates);

            return new Result(valid, signerCertificate, chain);
        } catch (CMSException e) {
            // Includes a digest mismatch (tampering) and an invalid
            // signature: both are simply "not a valid signature", not an
            // unexpected error.
            return Result.invalid();
        } catch (IOException | CertificateException | org.bouncycastle.operator.OperatorCreationException
                | RuntimeException e) {
            // Any other unexpected parsing problem (malformed ASN.1,
            // missing fields, ...): still just an invalid signature, never
            // an exception out of this helper.
            return Result.invalid();
        }
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
    private static List<X509Certificate> orderSignerFirst(X509Certificate signer, List<X509Certificate> certificates) {
        if (signer == null) {
            return List.copyOf(certificates);
        }
        List<X509Certificate> remaining = new ArrayList<>(certificates);
        removeByEncodedValue(remaining, signer);

        List<X509Certificate> ordered = new ArrayList<>();
        ordered.add(signer);

        X509Certificate current = signer;
        while (true) {
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
        } catch (CertificateException e) {
            return false;
        }
    }
}
