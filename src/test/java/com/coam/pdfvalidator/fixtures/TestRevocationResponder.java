package com.coam.pdfvalidator.fixtures;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Test-only helper that plays the role of a real OCSP responder/CRL
 * distribution point for T10's revocation-checking tests: builds real,
 * cryptographically signed OCSP responses and CRLs with Bouncy Castle,
 * served by {@link TestHttpServer}. Never use this in production code.
 */
public final class TestRevocationResponder {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestRevocationResponder() {
    }

    public enum OcspOutcome {
        GOOD, REVOKED, UNKNOWN_STATUS
    }

    /** A real, correctly-signed OCSP response (echoing the request's nonce, if any) for the given outcome. */
    public static byte[] ocspResponse(byte[] requestBytes, X509Certificate issuer, PrivateKey issuerKey, OcspOutcome outcome)
            throws Exception {
        return ocspResponse(requestBytes, issuer, issuerKey, outcome, java.time.Duration.ZERO, java.time.Duration.ofDays(1));
    }

    /** Same as {@link #ocspResponse}, but with an explicit {@code thisUpdate} offset (from now) and validity window, for staleness tests. */
    public static byte[] ocspResponseWithFreshness(
            byte[] requestBytes, X509Certificate issuer, PrivateKey issuerKey, OcspOutcome outcome,
            java.time.Duration thisUpdateOffset, java.time.Duration validFor) throws Exception {
        return ocspResponse(requestBytes, issuer, issuerKey, outcome, thisUpdateOffset, validFor);
    }

    private static byte[] ocspResponse(
            byte[] requestBytes, X509Certificate issuer, PrivateKey issuerKey, OcspOutcome outcome,
            java.time.Duration thisUpdateOffset, java.time.Duration validFor) throws Exception {
        OCSPReq request = new OCSPReq(requestBytes);
        Req[] requestList = request.getRequestList();
        CertificateID certId = requestList[0].getCertID();

        RespID responderId = new RespID(new JcaX509CertificateHolder(issuer).getSubject());
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(responderId);

        CertificateStatus status = switch (outcome) {
            case GOOD -> null; // BC convention: null CertificateStatus means "good"
            case REVOKED -> new RevokedStatus(Date.from(Instant.now().minusSeconds(3600)), CRLReason.keyCompromise);
            case UNKNOWN_STATUS -> new UnknownStatus();
        };

        Date thisUpdate = Date.from(Instant.now().plus(thisUpdateOffset));
        Date nextUpdate = Date.from(Instant.now().plus(thisUpdateOffset).plus(validFor));
        builder.addResponse(certId, status, thisUpdate, nextUpdate, null);

        Extension requestNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (requestNonce != null) {
            builder.setResponseExtensions(new Extensions(
                    new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, requestNonce.getExtnValue())));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);
        BasicOCSPResp basicResp = builder.build(signer, null, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp).getEncoded();
    }

    /**
     * A syntactically valid OCSP response claiming to be from {@code
     * issuer} (same responder identity), but actually signed by an
     * unrelated throwaway key -- signature verification against the real
     * issuer's public key must fail.
     */
    public static byte[] ocspResponseWithBadSignature(byte[] requestBytes, X509Certificate issuer) throws Exception {
        OCSPReq request = new OCSPReq(requestBytes);
        CertificateID certId = request.getRequestList()[0].getCertID();

        RespID responderId = new RespID(new JcaX509CertificateHolder(issuer).getSubject());
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(responderId);
        Date now = new Date();
        builder.addResponse(certId, null, now, new Date(now.getTime() + 86_400_000L), null);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair throwawayKeyPair = generator.generateKeyPair();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(throwawayKeyPair.getPrivate());
        BasicOCSPResp basicResp = builder.build(signer, null, now);
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp).getEncoded();
    }

    /** A real, correctly-signed CRL listing {@code revokedSerials} as revoked, with the given {@code nextUpdate}. */
    public static byte[] crl(X509Certificate issuer, PrivateKey issuerKey, List<BigInteger> revokedSerials, Instant nextUpdate)
            throws Exception {
        Date now = new Date();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new JcaX509CertificateHolder(issuer).getSubject(), now);
        crlBuilder.setNextUpdate(Date.from(nextUpdate));
        for (BigInteger serial : revokedSerials) {
            crlBuilder.addCRLEntry(serial, now, CRLReason.keyCompromise);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);
        X509CRLHolder holder = crlBuilder.build(signer);
        return holder.getEncoded();
    }
}
