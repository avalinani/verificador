package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.port.RevocationChecker;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;

/**
 * {@link RevocationChecker} adapter: OCSP first ({@link OcspClient}), CRL as
 * a fallback ({@link CrlClient}) when OCSP is unavailable or inconclusive.
 * Optional feature (README section on revocation): bounded by a strict
 * per-request {@code timeout} (default 2 s, {@code
 * pdfvalidator.revocation.timeout}) and a response size cap ({@code
 * pdfvalidator.revocation.max-response-bytes}), and never lets a network,
 * protocol or verification failure escape as an exception -- every such
 * failure is reported as {@link RevocationState#UNKNOWN} with a reason,
 * exactly like {@link OcspClient}/{@link CrlClient} document.
 *
 * <p><b>SSRF guard</b>: {@link RevocationUrlGuard} rejects any AIA/CDP URL
 * that is not {@code http}/{@code https}, or that resolves to a
 * private/loopback address -- a hostile or misissued certificate must never
 * be able to make this server contact an internal service. The guard is
 * disabled only via the package-private testing constructor below (used by
 * this project's own tests, which run a local HTTP server on {@code
 * localhost}); production wiring ({@code AdapterConfiguration}) always uses
 * the public constructor, which keeps it enabled.
 */
public final class CompositeRevocationChecker implements RevocationChecker {

    private final OcspClient ocspClient;
    private final CrlClient crlClient;

    public CompositeRevocationChecker(Duration timeout, long maxResponseBytes) {
        this(timeout, maxResponseBytes, false, HostResolver.systemDefault());
    }

    /**
     * Test-only: {@code allowPrivateAddressesForTesting} disables the SSRF
     * guard so tests can point AIA/CDP URLs at a local HTTP server, and
     * {@code resolver} lets a test prove the DNS-rebinding protection itself
     * (resolve once, connect to that exact address -- see {@link
     * RevocationUrlGuard} and {@link PinnedHttpClient}). Never called from
     * production wiring.
     */
    CompositeRevocationChecker(
            Duration timeout, long maxResponseBytes, boolean allowPrivateAddressesForTesting, HostResolver resolver) {
        Provider bcProvider = new BouncyCastleProvider();
        this.ocspClient = new OcspClient(
                timeout, maxResponseBytes, allowPrivateAddressesForTesting, resolver, bcProvider);
        this.crlClient = new CrlClient(timeout, maxResponseBytes, allowPrivateAddressesForTesting, resolver);
    }

    @Override
    public RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer) {
        if (issuer == null) {
            return new RevocationStatus(RevocationState.UNKNOWN, null, "issuer certificate not available");
        }

        X509Certificate certificateX509;
        X509Certificate issuerX509;
        try {
            certificateX509 = decode(certificate.encoded());
            issuerX509 = decode(issuer.encoded());
        } catch (CertificateException e) {
            return new RevocationStatus(
                    RevocationState.UNKNOWN, null, "certificate could not be decoded for revocation checking");
        }

        boolean hasOcsp = !certificate.ocspUrls().isEmpty();
        boolean hasCrl = !certificate.crlUrls().isEmpty();
        if (!hasOcsp && !hasCrl) {
            return new RevocationStatus(RevocationState.UNKNOWN, null, "no OCSP/CRL URL available for this certificate");
        }

        if (hasOcsp) {
            RevocationStatus ocsp = ocspClient.check(certificateX509, issuerX509, certificate.ocspUrls());
            if (ocsp.state() != RevocationState.UNKNOWN || !hasCrl) {
                return ocsp;
            }
            RevocationStatus crl = crlClient.check(certificateX509, issuerX509, certificate.crlUrls());
            if (crl.state() != RevocationState.UNKNOWN) {
                return crl;
            }
            return new RevocationStatus(RevocationState.UNKNOWN, crl.source() != null ? crl.source() : ocsp.source(),
                    "OCSP: " + ocsp.detail() + "; CRL: " + crl.detail());
        }

        return crlClient.check(certificateX509, issuerX509, certificate.crlUrls());
    }

    private static X509Certificate decode(byte[] der) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }
}
