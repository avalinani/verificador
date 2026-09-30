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
import org.bouncycastle.asn1.x500.X500Name;
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
            List<X509Certificate> chain,
            PrivateKey rootPrivateKey) {

        /** Identity whose root private key is not exposed (most fixtures never need to issue further certificates). */
        public IssuedIdentity(
                X509Certificate rootCertificate,
                X509Certificate endEntityCertificate,
                PrivateKey endEntityPrivateKey,
                List<X509Certificate> chain) {
            this(rootCertificate, endEntityCertificate, endEntityPrivateKey, chain, null);
        }
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
                    List.of(eeCertificate, rootCertificate),
                    rootKeyPair.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build test PKI", e);
        }
    }

    /**
     * A signer certificate plus its issuer's certificate AND private key --
     * unlike {@link IssuedIdentity} (which only exposes the end-entity's
     * private key, since production code never needs to sign as a CA),
     * T10's revocation-checking tests need the issuer's private key too, to
     * play the role of a real OCSP responder/CRL issuer ({@code
     * TestRevocationResponder}).
     */
    public record RevocationTestIdentity(
            X509Certificate signerCertificate, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
    }

    /**
     * Same shape as {@link #issueSigningIdentity()}, but with the end-entity
     * certificate's AIA (OCSP)/CRL Distribution Point URLs set explicitly
     * (either may be {@code null} to omit that extension entirely), and
     * exposing the issuing root's own private key so a test can sign real
     * OCSP responses/CRLs as that issuer -- used by T10's revocation-
     * checking tests to point the certificate at a local test HTTP server
     * instead of the hardcoded {@code ocsp.example.org}/{@code
     * crl.example.org} placeholders {@link #issueSigningIdentity()} uses.
     */
    public static RevocationTestIdentity issueRevocationTestIdentity(String ocspUrl, String crlUrl) {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair eeKeyPair = generateRsaKeyPair();

            Date notBefore = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            X509Certificate rootCertificate = buildRootCertificate(rootKeyPair, notBefore, notAfter);
            X509Certificate eeCertificate = buildEndEntityCertificate(
                    rootCertificate, rootKeyPair.getPrivate(), eeKeyPair.getPublic(), notBefore, notAfter,
                    ocspUrl, crlUrl);

            return new RevocationTestIdentity(eeCertificate, rootCertificate, rootKeyPair.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build test PKI with custom revocation URLs", e);
        }
    }

    /**
     * Same shape as {@link #issueSigningIdentity()}, but the end-entity
     * certificate's own validity window ends well before "now" (and
     * therefore before the signing time a fixture built with this identity
     * signs at, which is also "now") -- while the root stays valid.
     * Reproduces a real-world case: a qualified signature made a few months
     * after its own signer certificate's {@code notAfter}. The root itself
     * is unaffected, so a caller validating the chain at "now" sees an
     * otherwise-trustable path whose leaf alone is expired.
     */
    public static IssuedIdentity issueSigningIdentityExpiredAtSigningTime() {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair eeKeyPair = generateRsaKeyPair();

            Date rootNotBefore = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000);
            Date rootNotAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
            Date eeNotBefore = new Date(System.currentTimeMillis() - 400L * 24 * 60 * 60 * 1000);
            Date eeNotAfter = new Date(System.currentTimeMillis() - 2L * 24 * 60 * 60 * 1000);

            X509Certificate rootCertificate = buildRootCertificate(rootKeyPair, rootNotBefore, rootNotAfter);
            X509Certificate eeCertificate = buildEndEntityCertificate(
                    rootCertificate, rootKeyPair.getPrivate(), eeKeyPair.getPublic(), eeNotBefore, eeNotAfter);

            return new IssuedIdentity(
                    rootCertificate,
                    eeCertificate,
                    eeKeyPair.getPrivate(),
                    List.of(eeCertificate, rootCertificate));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build test PKI with an end-entity expired at signing time", e);
        }
    }

    /**
     * A signer whose certificate expired two days ago but whose root was valid
     * long before that (root: 500 days ago to one year ahead; signer: 400 to
     * 2 days ago). Unlike {@link #issueSigningIdentityExpiredAtSigningTime()}
     * the root is also valid 30 days ago, so a trusted timestamp issued 30
     * days ago (see {@link #issueTsaIdentityUnder}) genuinely validates the
     * whole chain at its {@code genTime}, while "now" finds the signer
     * expired. Exposes the root key so a TSA can be issued under it.
     */
    public static IssuedIdentity issueExpiredSigner() {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair eeKeyPair = generateRsaKeyPair();
            long day = 24L * 60 * 60 * 1000;
            long now = System.currentTimeMillis();

            X509Certificate rootCertificate =
                    buildRootCertificate(rootKeyPair, new Date(now - 500 * day), new Date(now + 365 * day));
            X509Certificate eeCertificate = buildEndEntityCertificate(
                    rootCertificate, rootKeyPair.getPrivate(), eeKeyPair.getPublic(),
                    new Date(now - 400 * day), new Date(now - 2 * day));

            return new IssuedIdentity(
                    rootCertificate, eeCertificate, eeKeyPair.getPrivate(),
                    List.of(eeCertificate, rootCertificate), rootKeyPair.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build test PKI with an expired signer", e);
        }
    }

    /**
     * A TSA issued by {@code ca}'s root (so a trust store holding that root
     * trusts the TSA), valid from 450 days ago to one year ahead, declaring
     * {@code id-kp-timeStamping}. Requires an identity that exposes its root
     * key ({@link IssuedIdentity#rootPrivateKey()}). Contrast with
     * {@link #issueTsaIdentity()}, whose TSA hangs from its own private root
     * that nobody trusts.
     */
    public static TsaIdentity issueTsaIdentityUnder(IssuedIdentity ca) {
        if (ca.rootPrivateKey() == null) {
            throw new IllegalArgumentException("the identity does not expose its root private key");
        }
        try {
            KeyPair tsaKeyPair = generateRsaKeyPair();
            long day = 24L * 60 * 60 * 1000;
            long now = System.currentTimeMillis();
            X509Certificate tsaCertificate = buildTsaCertificate(
                    ca.rootCertificate(), ca.rootPrivateKey(), tsaKeyPair.getPublic(),
                    new Date(now - 450 * day), new Date(now + 365 * day));
            return new TsaIdentity(
                    tsaCertificate, tsaKeyPair.getPrivate(), List.of(tsaCertificate, ca.rootCertificate()));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build a TSA under the given root", e);
        }
    }

    /**
     * Same shape as {@link #issueSigningIdentity()}, but the end-entity
     * certificate's subject is the given {@code X500Name} instead of the
     * fixed {@code "CN=Spike Test Signer,O=COAM,C=ES"} -- used by T11f's
     * readable-DN test, which needs a subject carrying an {@code
     * emailAddress} (OID 1.2.840.113549.1.9.1) attribute that a real,
     * honestly-issued certificate (e.g. a Spanish DNIe/FNMT one) can also
     * carry.
     */
    public static IssuedIdentity issueSigningIdentityWithSubject(X500Name subject) {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair eeKeyPair = generateRsaKeyPair();

            Date notBefore = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            X509Certificate rootCertificate = buildRootCertificate(rootKeyPair, notBefore, notAfter);
            X509Certificate eeCertificate = buildEndEntityCertificate(
                    rootCertificate, rootKeyPair.getPrivate(), eeKeyPair.getPublic(), notBefore, notAfter,
                    "http://ocsp.example.org/ee", "http://crl.example.org/ee.crl", subject);

            return new IssuedIdentity(
                    rootCertificate,
                    eeCertificate,
                    eeKeyPair.getPrivate(),
                    List.of(eeCertificate, rootCertificate));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build test PKI with a custom subject", e);
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
        return issueTsaIdentity(java.time.Duration.ofDays(1));
    }

    /**
     * Same as {@link #issueTsaIdentity()}, but the TSA and its (self-made)
     * root are valid since {@code validSince} ago: what an attacker running
     * their own TSA does so that a back-dated timestamp still verifies (Bouncy
     * Castle rejects a token whose TSA certificate was not valid at its
     * {@code genTime}). Nobody trusts this root.
     */
    public static TsaIdentity issueTsaIdentity(java.time.Duration validSince) {
        try {
            KeyPair rootKeyPair = generateRsaKeyPair();
            KeyPair tsaKeyPair = generateRsaKeyPair();

            Date notBefore = new Date(System.currentTimeMillis() - validSince.toMillis());
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
        return buildEndEntityCertificate(rootCertificate, rootPrivateKey, eePublicKey, notBefore, notAfter,
                "http://ocsp.example.org/ee", "http://crl.example.org/ee.crl");
    }

    /** Same as the 5-argument overload, but with explicit (possibly {@code null}, to omit the extension) AIA/CDP URLs. */
    private static X509Certificate buildEndEntityCertificate(
            X509Certificate rootCertificate,
            PrivateKey rootPrivateKey,
            java.security.PublicKey eePublicKey,
            Date notBefore,
            Date notAfter,
            String ocspUrl,
            String crlUrl) throws Exception {
        return buildEndEntityCertificate(rootCertificate, rootPrivateKey, eePublicKey, notBefore, notAfter,
                ocspUrl, crlUrl, new X500Name("CN=Spike Test Signer,O=COAM,C=ES"));
    }

    /** Same as the 7-argument overload, but with an explicit subject {@code X500Name}. */
    private static X509Certificate buildEndEntityCertificate(
            X509Certificate rootCertificate,
            PrivateKey rootPrivateKey,
            java.security.PublicKey eePublicKey,
            Date notBefore,
            Date notAfter,
            String ocspUrl,
            String crlUrl,
            X500Name subject) throws Exception {

        org.bouncycastle.asn1.x500.X500Name issuer = subjectName(rootCertificate);

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
        if (ocspUrl != null) {
            certBuilder.addExtension(Extension.authorityInfoAccess, false,
                    new AuthorityInformationAccess(
                            AccessDescription.id_ad_ocsp,
                            new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        }
        if (crlUrl != null) {
            certBuilder.addExtension(Extension.cRLDistributionPoints, false,
                    new CRLDistPoint(new DistributionPoint[] {
                            new DistributionPoint(
                                    new DistributionPointName(new GeneralNames(
                                            new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))),
                                    null, null)
                    }));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
