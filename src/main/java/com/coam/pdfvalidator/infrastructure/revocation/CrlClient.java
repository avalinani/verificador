package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * CRL (RFC 5280) client, used as the fallback when OCSP is unavailable or
 * inconclusive: downloads the distribution point's CRL with a strict
 * timeout, verifies its signature against the issuer's public key and its
 * freshness, then looks up the certificate's serial number among the
 * revoked entries.
 *
 * <p>Never throws for a network, protocol or verification failure: every
 * failure mode maps to {@link RevocationState#UNKNOWN} with a stable,
 * non-sensitive {@code detail}, exactly like {@link OcspClient}.
 *
 * <p>Uses {@link PinnedHttpClient} (a raw-socket HTTP/1.1 client), not
 * {@code java.net.http.HttpClient}, for the same DNS-rebinding reason
 * documented on {@link RevocationUrlGuard} and {@link PinnedHttpClient}
 * themselves: the hostname is resolved exactly once by {@link
 * RevocationUrlGuard#resolve}, and the connection is pinned to that one
 * resolved address.
 */
final class CrlClient {

    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

    private final RevocationLimits limits;
    private final boolean allowPrivateAddresses;
    private final HostResolver resolver;

    CrlClient(Duration timeout, long maxResponseBytes, boolean allowPrivateAddresses, HostResolver resolver) {
        this(RevocationLimits.withDefaults(timeout, maxResponseBytes), allowPrivateAddresses, resolver);
    }

    CrlClient(RevocationLimits limits, boolean allowPrivateAddresses, HostResolver resolver) {
        this.limits = limits;
        this.allowPrivateAddresses = allowPrivateAddresses;
        this.resolver = resolver;
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
        return UrlFallback.firstConclusive(
                urls, deadline, limits.timeout(), "no CRL URL available for this certificate",
                (url, attempt) -> checkOne(certificate, issuer, url, attempt));
    }

    private RevocationStatus checkOne(
            X509Certificate certificate, X509Certificate issuer, String url, Deadline attempt) {
        RevocationUrlGuard.ValidatedTarget target;
        try {
            target = RevocationUrlGuard.resolve(url, allowPrivateAddresses, resolver, attempt.remaining());
        } catch (RevocationUrlRejectedException e) {
            return unknown(url, "CRL URL rejected: " + e.getMessage());
        }

        byte[] body;
        try {
            PinnedHttpClient.Response response =
                    PinnedHttpClient.send(target, "GET", null, Map.of(), attempt.remaining(),
                            limits.maxResponseBytes(), limits.httpLimits());
            if (response.statusCode() != 200) {
                return unknown(url, "CRL distribution point returned HTTP " + response.statusCode());
            }
            body = response.body();
        } catch (PinnedHttpClient.ResponseTooLargeException e) {
            return unknown(url, "CRL response exceeds the size limit");
        } catch (SocketTimeoutException e) {
            return unknown(url, "CRL request timed out");
        } catch (IOException e) {
            return unknown(url, "CRL request failed (network error)");
        } catch (RuntimeException e) {
            // Defense in depth: PinnedHttpClient documents "never throws unchecked", but this
            // client must never propagate one either, whatever its actual cause.
            return unknown(url, "CRL request failed (unexpected error)");
        }

        return evaluate(certificate, issuer, url, body);
    }

    private RevocationStatus evaluate(X509Certificate certificate, X509Certificate issuer, String url, byte[] body) {
        X509CRL crl;
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            crl = (X509CRL) factory.generateCRL(new ByteArrayInputStream(body));
        } catch (GeneralSecurityException | ClassCastException e) {
            return unknown(url, "CRL could not be parsed");
        }

        try {
            crl.verify(issuer.getPublicKey());
        } catch (GeneralSecurityException e) {
            return unknown(url, "CRL signature is invalid");
        }

        Instant now = Instant.now();
        if (crl.getThisUpdate() != null && crl.getThisUpdate().toInstant().isAfter(now.plus(CLOCK_SKEW))) {
            return unknown(url, "stale CRL (thisUpdate is in the future)");
        }
        if (crl.getNextUpdate() != null && now.isAfter(crl.getNextUpdate().toInstant().plus(CLOCK_SKEW))) {
            return unknown(url, "stale CRL (past nextUpdate)");
        }

        X509CRLEntry entry = crl.getRevokedCertificate(certificate.getSerialNumber());
        if (entry == null) {
            return new RevocationStatus(RevocationState.GOOD, url, null);
        }
        String detail = "revoked at " + entry.getRevocationDate().toInstant()
                + (entry.getRevocationReason() != null ? " (reason " + entry.getRevocationReason() + ")" : "");
        return new RevocationStatus(RevocationState.REVOKED, url, detail);
    }

    private static RevocationStatus unknown(String source, String detail) {
        return new RevocationStatus(RevocationState.UNKNOWN, source, detail);
    }
}
