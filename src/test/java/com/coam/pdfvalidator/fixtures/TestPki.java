package com.coam.pdfvalidator.fixtures;

import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Test-only helper that builds an in-memory RSA-2048 PKI (root CA + end-entity
 * signing certificate) with Bouncy Castle, used to sign PDFs in the signature
 * spike tests. Never use this in production code.
 */
public final class TestPki {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestPki() {
    }

    /** Root CA certificate + end-entity signing certificate/key, ready to sign a PDF. */
    public record IssuedIdentity(
            X509Certificate rootCertificate,
            X509Certificate endEntityCertificate,
            PrivateKey endEntityPrivateKey,
            List<X509Certificate> chain) {
    }

    /** A TSA (Time-Stamping Authority) certificate/key, ready to sign RFC 3161 timestamp tokens. */
    public record TsaIdentity(X509Certificate certificate, PrivateKey privateKey, List<X509Certificate> chain) {
    }

    /**
     * A three-tier identity (root CA -&gt; intermediate CA -&gt; end-entity),
     * for chain-validation tests that need an actual intermediate to be
     * missing from a presented chain (as opposed to {@link #issueSigningIdentity()}'s
     * direct root-to-end-entity chain, where there is no intermediate to omit).
     */
    public record ThreeTierIdentity(
            X509Certificate rootCertificate,
            X509Certificate intermediateCertificate,
            X509Certificate endEntityCertificate,
            List<X509Certificate> chain) {
    }

    public static IssuedIdentity issueSigningIdentity() {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair eeKeyPair = generateRsaKeyPair();

            Date notBefore = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            X509Certificate rootCertificate = buildRootCertificate(rootKeyPair, notBefore, notAfter);
            X509Certificate eeCertificate = buildEndEntityCertificate(
                    rootCertificate, rootKeyPair.getPrivate(), eeKeyPair.getPublic(), notBefore, notAfter);

            return new IssuedIdentity(
                    rootCertificate,
                    eeCertificate,
                    eeKeyPair.getPrivate(),
                    List.of(eeCertificate, rootCertificate));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build test PKI", e);
        }
    }

    /** A root CA, an intermediate CA it issued, and an end-entity certificate issued by that intermediate. */
    public static ThreeTierIdentity issueThreeTierIdentity() {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair intermediateKeyPair = generateRsaKeyPair();
            KeyPair eeKeyPair = generateRsaKeyPair();

            Date notBefore = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            X509Certificate rootCertificate = buildRootCertificate(rootKeyPair, notBefore, notAfter);
            X509Certificate intermediateCertificate = buildIntermediateCertificate(
                    rootCertificate, rootKeyPair.getPrivate(), intermediateKeyPair.getPublic(), notBefore, notAfter);
            X509Certificate eeCertificate = buildEndEntityCertificateIssuedBy(
                    intermediateCertificate, intermediateKeyPair.getPrivate(), eeKeyPair.getPublic(),
                    notBefore, notAfter);

            return new ThreeTierIdentity(
                    rootCertificate,
                    intermediateCertificate,
                    eeCertificate,
                    List.of(eeCertificate, intermediateCertificate, rootCertificate));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build three-tier test PKI", e);
        }
    }

    private static X509Certificate buildIntermediateCertificate(
            X509Certificate rootCertificate,
            PrivateKey rootPrivateKey,
            java.security.PublicKey intermediatePublicKey,
            Date notBefore,
            Date notAfter) throws Exception {

        org.bouncycastle.asn1.x500.X500Name issuer = subjectName(rootCertificate);
        org.bouncycastle.asn1.x500.X500Name subject =
                new org.bouncycastle.asn1.x500.X500Name("CN=Spike Test Intermediate CA,O=COAM,C=ES");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis() + 3),
                notBefore,
                notAfter,
                subject,
                intermediatePublicKey);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    private static X509Certificate buildEndEntityCertificateIssuedBy(
            X509Certificate issuerCertificate,
            PrivateKey issuerPrivateKey,
            java.security.PublicKey eePublicKey,
            Date notBefore,
            Date notAfter) throws Exception {

        org.bouncycastle.asn1.x500.X500Name issuer = subjectName(issuerCertificate);
        org.bouncycastle.asn1.x500.X500Name subject =
                new org.bouncycastle.asn1.x500.X500Name("CN=Spike Test Signer (three-tier),O=COAM,C=ES");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis() + 4),
                notBefore,
                notAfter,
                subject,
                eePublicKey);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(issuerPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    /** A TSA identity whose certificate declares the {@code id-kp-timeStamping} extended key usage. */
    public static TsaIdentity issueTsaIdentity() {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair tsaKeyPair = generateRsaKeyPair();

            Date notBefore = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            X509Certificate rootCertificate = buildRootCertificate(rootKeyPair, notBefore, notAfter);
            X509Certificate tsaCertificate = buildTsaCertificate(
                    rootCertificate, rootKeyPair.getPrivate(), tsaKeyPair.getPublic(), notBefore, notAfter);

            return new TsaIdentity(tsaCertificate, tsaKeyPair.getPrivate(), List.of(tsaCertificate, rootCertificate));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build test TSA identity", e);
        }
    }

    private static X509Certificate buildTsaCertificate(
            X509Certificate rootCertificate,
            PrivateKey rootPrivateKey,
            java.security.PublicKey tsaPublicKey,
            Date notBefore,
            Date notAfter) throws Exception {

        org.bouncycastle.asn1.x500.X500Name issuer = subjectName(rootCertificate);
        org.bouncycastle.asn1.x500.X500Name subject =
                new org.bouncycastle.asn1.x500.X500Name("CN=Spike Test TSA,O=COAM,C=ES");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis() + 2),
                notBefore,
                notAfter,
                subject,
                tsaPublicKey);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        // RFC 3161 requires this extension to be present, critical, and to
        // contain ONLY id-kp-timeStamping (Bouncy Castle's own
        // TimeStampTokenGenerator enforces exactly this at generation time,
        // so a "missing EKU" TSA identity cannot be built through it at all
        // -- see reissueWithoutTimestampingEku for how that case is tested).
        certBuilder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    /**
     * Rebuilds {@code original} with the same subject, issuer, serial
     * number and public key, but a different (non-timeStamping) extended
     * key usage, self-signed by a fresh throwaway key. Bouncy Castle's own
     * {@code TimeStampTokenGenerator} refuses to issue a token whose TSA
     * certificate does not (correctly) declare {@code id-kp-timeStamping}
     * as its sole extended key usage, so a test proving the domain reports
     * this anomaly must instead swap the certificate <em>after</em> a
     * validly-issued token's own certificate: since the substitute keeps
     * the original's public key, the token's already-produced CMS
     * signature still verifies against it, and its issuer/serial number
     * (used for {@code SignerId} matching) is unchanged -- only the
     * extended key usage differs, and neither this substitute's own
     * signing key nor its issuer relationship is otherwise checked.
     */
    public static X509Certificate reissueWithoutTimestampingEku(X509Certificate original) {
        try {
            KeyPair throwawayKeyPair = generateRsaKeyPair();

            org.bouncycastle.asn1.x500.X500Name issuer = issuerName(original);
            org.bouncycastle.asn1.x500.X500Name subject = subjectName(original);

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    original.getSerialNumber(),
                    original.getNotBefore(),
                    original.getNotAfter(),
                    subject,
                    original.getPublicKey());

            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certBuilder.addExtension(Extension.extendedKeyUsage, true,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(throwawayKeyPair.getPrivate());

            X509CertificateHolder holder = certBuilder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to reissue TSA certificate without timeStamping EKU", e);
        }
    }

    /**
     * Rebuilds a BC {@code X500Name} from an existing certificate's subject
     * or issuer field, preserving the exact original RDN encoding order.
     *
     * <p>The naive alternative -- {@code new X500Name(principal.getName())},
     * re-parsing the JDK's RFC 2253 string form -- silently round-trips
     * through a string representation that reverses RDN order relative to
     * however the name was originally DER-encoded (a BC {@code
     * X500Name(String)} literal encodes RDNs in the same left-to-right
     * order they appear in the string, while JDK's RFC 2253 rendering
     * always reverses whatever DER order it finds). Two certificates built
     * this way end up with byte-different (though logically identical)
     * issuer/subject DNs: BC's own DN comparisons (used for CMS/CAdES
     * verification elsewhere in this codebase) tolerate that, but the JDK's
     * PKIX {@code X509CertSelector}/{@code X500Principal} comparisons used
     * by {@code PkixCertificateChainValidator} do not, since {@link
     * javax.security.auth.x500.X500Principal#equals} is defined over the
     * RFC 2253 string form, which differs when the encoded RDN order does.
     * Reconstructing the {@code X500Name} straight from the principal's own
     * DER bytes (as this method does) avoids the round trip entirely.
     */
    private static org.bouncycastle.asn1.x500.X500Name subjectName(X509Certificate certificate) {
        return org.bouncycastle.asn1.x500.X500Name.getInstance(
                org.bouncycastle.asn1.ASN1Sequence.getInstance(certificate.getSubjectX500Principal().getEncoded()));
    }

    /** Same as {@link #subjectName}, but for a certificate's issuer field. */
    private static org.bouncycastle.asn1.x500.X500Name issuerName(X509Certificate certificate) {
        return org.bouncycastle.asn1.x500.X500Name.getInstance(
                org.bouncycastle.asn1.ASN1Sequence.getInstance(certificate.getIssuerX500Principal().getEncoded()));
    }

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate buildRootCertificate(KeyPair rootKeyPair, Date notBefore, Date notAfter)
            throws Exception {
        org.bouncycastle.asn1.x500.X500Name subject =
                new org.bouncycastle.asn1.x500.X500Name("CN=Spike Test Root CA,O=COAM,C=ES");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                subject,
                rootKeyPair.getPublic());

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootKeyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    private static X509Certificate buildEndEntityCertificate(
            X509Certificate rootCertificate,
            PrivateKey rootPrivateKey,
            java.security.PublicKey eePublicKey,
            Date notBefore,
            Date notAfter) throws Exception {

        org.bouncycastle.asn1.x500.X500Name issuer = subjectName(rootCertificate);
        org.bouncycastle.asn1.x500.X500Name subject =
                new org.bouncycastle.asn1.x500.X500Name("CN=Spike Test Signer,O=COAM,C=ES");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis() + 1),
                notBefore,
                notAfter,
                subject,
                eePublicKey);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        certBuilder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(
                        AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.org/ee")));
        certBuilder.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[] {
                        new DistributionPoint(
                                new DistributionPointName(new GeneralNames(
                                        new GeneralName(GeneralName.uniformResourceIdentifier,
                                                "http://crl.example.org/ee.crl"))),
                                null, null)
                }));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
