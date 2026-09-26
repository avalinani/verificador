package com.coam.pdfvalidator.spike;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
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

        org.bouncycastle.asn1.x500.X500Name issuer =
                new org.bouncycastle.asn1.x500.X500Name(rootCertificate.getSubjectX500Principal().getName());
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

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(rootPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
