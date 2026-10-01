package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * OCSP (RFC 6960) client: builds a request for one certificate/issuer pair
 * (with a nonce, to detect a replayed response), POSTs it to a distribution
 * point URL with a strict timeout, and verifies the response's signature,
 * certificate identifier, freshness and (when present) nonce echo before
 * trusting its {@code GOOD}/{@code REVOKED} verdict.
 *
 * <p>Never throws for a network, protocol or verification failure: every
 * failure mode maps to {@link RevocationState#UNKNOWN} with a stable, non-
 * sensitive {@code detail} (README section on revocation checking documents
 * each one). This mirrors this project's existing convention for the other
 * "never abort the whole analysis" adapters ({@code BcSignatureVerifier},
 * {@code SignatureTimestampVerifier}).
 */
final class OcspClient {

    private static final System.Logger LOG = System.getLogger(OcspClient.class.getName());
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    /** One shared instance: SecureRandom is thread-safe, and re-seeding a fresh one per request is wasteful. */
    private static final SecureRandom NONCE_RANDOM = new SecureRandom();

    private final RevocationLimits limits;
    private final boolean allowPrivateAddresses;
    private final HostResolver resolver;
    private final Provider bcProvider;

    OcspClient(Duration timeout, long maxResponseBytes, boolean allowPrivateAddresses,
            HostResolver resolver, Provider bcProvider) {
        this(RevocationLimits.withDefaults(timeout, maxResponseBytes), allowPrivateAddresses, resolver, bcProvider);
    }

    OcspClient(RevocationLimits limits, boolean allowPrivateAddresses, HostResolver resolver, Provider bcProvider) {
        this.limits = limits;
        this.allowPrivateAddresses = allowPrivateAddresses;
        this.resolver = resolver;
        this.bcProvider = bcProvider;
    }

    /** {@link #check(X509Certificate, X509Certificate, List, Deadline)} under a fresh total budget. */
    RevocationStatus check(X509Certificate certificate, X509Certificate issuer, List<String> urls) {
        return check(certificate, issuer, urls, Deadline.after(limits.totalTimeout()));
    }

    /**
     * Tries each URL in order, returning the first non-{@code UNKNOWN} result, or the last {@code UNKNOWN}
     * one. Every attempt (DNS, connect, response) runs under the smaller of the per-request timeout and the
     * shared {@code deadline}; once that is spent, the remaining URLs are not contacted at all.
     */
    RevocationStatus check(X509Certificate certificate, X509Certificate issuer, List<String> urls, Deadline deadline) {
        RevocationStatus last = unknown(null, "no OCSP URL available for this certificate");
        for (String url : urls) {
            if (deadline.expired()) {
                return unknown(null, Deadline.EXHAUSTED_DETAIL);
            }
            last = checkOne(certificate, issuer, url, deadline.capped(limits.timeout()));
            if (last.state() != RevocationState.UNKNOWN) {
                return last;
            }
        }
        return last;
    }

    private RevocationStatus checkOne(
            X509Certificate certificate, X509Certificate issuer, String url, Deadline attempt) {
        RevocationUrlGuard.ValidatedTarget target;
        try {
            target = RevocationUrlGuard.resolve(url, allowPrivateAddresses, resolver, attempt.remaining());
        } catch (RevocationUrlRejectedException e) {
            return unknown(url, "OCSP URL rejected: " + e.getMessage());
        }

        CertificateID certId;
        byte[] nonce = new byte[16];
        byte[] requestBytes;
        try {
            certId = new JcaCertificateID(
                    new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build().get(CertificateID.HASH_SHA1),
                    issuer, certificate.getSerialNumber());
            NONCE_RANDOM.nextBytes(nonce);
            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            reqBuilder.addRequest(certId);
            reqBuilder.setRequestExtensions(new Extensions(
                    new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce))));
            OCSPReq request = reqBuilder.build();
            requestBytes = request.getEncoded();
        } catch (OCSPException | OperatorCreationException | CertificateEncodingException | IOException e) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to build OCSP request", e);
            return unknown(url, "OCSP request could not be built");
        }

        byte[] responseBytes;
        try {
            PinnedHttpClient.Response httpResponse = PinnedHttpClient.send(
                    target, "POST", requestBytes, Map.of("Content-Type", "application/ocsp-request"),
                    attempt.remaining(), limits.maxResponseBytes(), limits.httpLimits());
            if (httpResponse.statusCode() != 200) {
                return unknown(url, "OCSP responder returned HTTP " + httpResponse.statusCode());
            }
            responseBytes = httpResponse.body();
        } catch (PinnedHttpClient.ResponseTooLargeException e) {
            return unknown(url, "OCSP response exceeds the size limit");
        } catch (SocketTimeoutException e) {
            return unknown(url, "OCSP request timed out");
        } catch (IOException e) {
            return unknown(url, "OCSP request failed (network error)");
        } catch (RuntimeException e) {
            // Defense in depth: PinnedHttpClient documents "never throws unchecked", but this
            // client must never propagate one either, whatever its actual cause.
            LOG.log(System.Logger.Level.DEBUG, "OCSP request failed unexpectedly", e);
            return unknown(url, "OCSP request failed (unexpected error)");
        }

        return evaluate(issuer, url, certId, nonce, responseBytes);
    }

    private RevocationStatus evaluate(
            X509Certificate issuer, String url,
            CertificateID certId, byte[] requestNonce, byte[] responseBytes) {
        BasicOCSPResp basicResp;
        try {
            OCSPResp resp = new OCSPResp(responseBytes);
            if (resp.getStatus() != OCSPResp.SUCCESSFUL) {
                return unknown(url, "OCSP responder did not return a successful response");
            }
            Object responseObject = resp.getResponseObject();
            if (!(responseObject instanceof BasicOCSPResp basic)) {
                return unknown(url, "malformed OCSP response");
            }
            basicResp = basic;
        } catch (OCSPException | IOException e) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to parse OCSP response", e);
            return unknown(url, "OCSP response could not be parsed");
        }

        Extension responseNonceExt = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (responseNonceExt != null) {
            ASN1OctetString responseNonce = ASN1OctetString.getInstance(responseNonceExt.getExtnValue());
            if (!java.util.Arrays.equals(responseNonce.getOctets(), requestNonce)) {
                return unknown(url, "OCSP nonce mismatch (possible replay)");
            }
        }

        PublicKey responderKey;
        try {
            responderKey = resolveResponderKey(basicResp, issuer);
        } catch (CertificateEncodingException | OCSPException e) {
            return unknown(url, "OCSP responder certificate could not be verified");
        }
        if (responderKey == null) {
            return unknown(url, "OCSP responder certificate not recognized (neither the issuer nor a valid delegated responder)");
        }

        try {
            if (!basicResp.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(bcProvider).build(responderKey))) {
                return unknown(url, "OCSP response signature is invalid");
            }
        } catch (OCSPException | OperatorCreationException e) {
            return unknown(url, "OCSP response signature could not be verified");
        }

        SingleResp match = null;
        for (SingleResp singleResp : basicResp.getResponses()) {
            if (singleResp.getCertID().equals(certId)) {
                match = singleResp;
                break;
            }
        }
        if (match == null) {
            return unknown(url, "OCSP response does not include the requested certificate");
        }

        Instant now = Instant.now();
        Instant thisUpdate = match.getThisUpdate().toInstant();
        if (thisUpdate.isAfter(now.plus(CLOCK_SKEW))) {
            return unknown(url, "stale OCSP response (thisUpdate is in the future)");
        }
        if (match.getNextUpdate() != null) {
            Instant nextUpdate = match.getNextUpdate().toInstant();
            if (now.isAfter(nextUpdate.plus(CLOCK_SKEW))) {
                return unknown(url, "stale OCSP response (past nextUpdate)");
            }
        }

        CertificateStatus status = match.getCertStatus();
        if (status == null) {
            return new RevocationStatus(RevocationState.GOOD, url, null);
        }
        if (status instanceof RevokedStatus revoked) {
            String detail = "revoked at " + revoked.getRevocationTime().toInstant()
                    + (revoked.hasRevocationReason() ? " (reason code " + revoked.getRevocationReason() + ")" : "");
            return new RevocationStatus(RevocationState.REVOKED, url, detail);
        }
        return unknown(url, "OCSP responder does not know this certificate");
    }

    /**
     * Resolves the public key that must have signed {@code basicResp}: the
     * issuer itself when {@link BasicOCSPResp#getResponderId()} matches it
     * directly, or an embedded delegated responder certificate when one
     * matches, is issued by {@code issuer}, and carries the {@code
     * id-kp-OCSPSigning} extended key usage. Returns {@code null} when
     * neither applies.
     */
    private PublicKey resolveResponderKey(BasicOCSPResp basicResp, X509Certificate issuer)
            throws CertificateEncodingException, OCSPException {
        X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);

        // Direct case: the issuer itself signed the response.
        if (matchesResponderId(basicResp, issuerHolder)) {
            return issuer.getPublicKey();
        }

        // Delegated case: an embedded responder certificate, issued by the
        // issuer, declaring id-kp-OCSPSigning.
        for (X509CertificateHolder candidate : basicResp.getCerts()) {
            if (!matchesResponderId(basicResp, candidate)) {
                continue;
            }
            try {
                X509Certificate candidateCert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                        .setProvider(bcProvider).getCertificate(candidate);
                candidateCert.verify(issuer.getPublicKey());
                if (!hasOcspSigningEku(candidateCert)) {
                    continue;
                }
                return candidateCert.getPublicKey();
            } catch (Exception e) {
                LOG.log(System.Logger.Level.DEBUG, "Delegated OCSP responder candidate rejected", e);
            }
        }
        return null;
    }

    /**
     * Compares {@code basicResp}'s claimed responder identity against {@code
     * holder} by both forms {@link org.bouncycastle.cert.ocsp.RespID} can
     * take (by name, or by a SHA-1 hash of the subject public key) --
     * responders are free to use either.
     */
    private boolean matchesResponderId(BasicOCSPResp basicResp, X509CertificateHolder holder) {
        org.bouncycastle.cert.ocsp.RespID byName = new org.bouncycastle.cert.ocsp.RespID(holder.getSubject());
        if (basicResp.getResponderId().equals(byName)) {
            return true;
        }
        try {
            org.bouncycastle.operator.DigestCalculator digestCalculator =
                    new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider)
                            .build().get(org.bouncycastle.cert.ocsp.RespID.HASH_SHA1);
            org.bouncycastle.cert.ocsp.RespID byKey =
                    new org.bouncycastle.cert.ocsp.RespID(holder.getSubjectPublicKeyInfo(), digestCalculator);
            return basicResp.getResponderId().equals(byKey);
        } catch (OperatorCreationException | OCSPException e) {
            return false;
        }
    }

    private static boolean hasOcspSigningEku(X509Certificate certificate) {
        try {
            List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            return extendedKeyUsage != null && extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
        } catch (java.security.cert.CertificateParsingException e) {
            return false;
        }
    }

    private static RevocationStatus unknown(String source, String detail) {
        return new RevocationStatus(RevocationState.UNKNOWN, source, detail);
    }
}
