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
import java.util.List;

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

    private static final System.Logger LOGGER = System.getLogger(CompositeRevocationChecker.class.getName());

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
            RevocationStatus ocsp = checkOcspSafely(certificateX509, issuerX509, certificate.ocspUrls());
            if (ocsp.state() != RevocationState.UNKNOWN || !hasCrl) {
                return ocsp;
            }
            RevocationStatus crl = checkCrlSafely(certificateX509, issuerX509, certificate.crlUrls());
            if (crl.state() != RevocationState.UNKNOWN) {
                return crl;
            }
            return new RevocationStatus(RevocationState.UNKNOWN, crl.source() != null ? crl.source() : ocsp.source(),
                    "OCSP: " + ocsp.detail() + "; CRL: " + crl.detail());
        }

        return checkCrlSafely(certificateX509, issuerX509, certificate.crlUrls());
    }

    /**
     * Defense in depth: {@link OcspClient}/{@link CrlClient} already document "never throws",
     * but this adapter must never propagate an exception from them either, whatever its cause.
     */
    private RevocationStatus checkOcspSafely(X509Certificate certificate, X509Certificate issuer, List<String> urls) {
        return safely("OCSP", () -> ocspClient.check(certificate, issuer, urls));
    }

    private RevocationStatus checkCrlSafely(X509Certificate certificate, X509Certificate issuer, List<String> urls) {
        return safely("CRL", () -> crlClient.check(certificate, issuer, urls));
    }

    /**
     * Runs {@code action}, catching any {@link RuntimeException} it throws
     * and reporting it as {@link RevocationState#UNKNOWN} instead of letting
     * it escape (T10b). Only the exception's own class name is logged --
     * never {@link Throwable#getMessage()} or any part of the certificate
     * being checked -- since the underlying cause could carry
     * network/response detail that must not reach the server log verbatim.
     * Package-private (rather than private) specifically so this catch-and-
     * log behavior can be unit-tested directly, the same convention already
     * used elsewhere in this codebase (e.g. {@code
     * PreflightPdfaValidator#mapErrors}) for a seam that is otherwise
     * impractical to drive through the real adapters it wraps.
     */
    RevocationStatus safely(String checkName, java.util.function.Supplier<RevocationStatus> action) {
        try {
            return action.get();
        } catch (RuntimeException e) {
            LOGGER.log(System.Logger.Level.WARNING,
                    checkName + " revocation check failed with an unexpected " + e.getClass().getSimpleName());
            return new RevocationStatus(RevocationState.UNKNOWN, null, checkName + " check failed (unexpected error)");
        }
    }

    private static X509Certificate decode(byte[] der) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }
}
