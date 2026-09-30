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
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * {@link RevocationChecker} adapter: OCSP first ({@link OcspClient}), CRL as
 * a fallback ({@link CrlClient}) when OCSP is unavailable or inconclusive.
 * Optional feature (README section on revocation): every bound lives in
 * {@link RevocationLimits} ({@code pdfvalidator.revocation.*}) and it never
 * lets a network, protocol or verification failure escape as an exception --
 * every such failure is reported as {@link RevocationState#UNKNOWN} with a
 * reason, exactly like {@link OcspClient}/{@link CrlClient} document.
 *
 * <p><b>Effort bounds (T21)</b>: the URLs of each certificate are
 * de-duplicated and capped per method; each request runs under a per-request
 * timeout <em>and</em> one shared {@link Deadline} covering the whole
 * revocation check of a signature ({@link #checkPath}: OCSP and CRL attempts
 * of every certificate of the path). When that budget is spent the remaining
 * attempts are not made and the outcome is {@code UNKNOWN}
 * ({@link Deadline#EXHAUSTED_DETAIL}), which the verdict policy treats as
 * fail-closed.
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
    private final RevocationLimits limits;
    private final LongSupplier nanoClock;

    public CompositeRevocationChecker(RevocationLimits limits) {
        this(limits, false, HostResolver.systemDefault(), System::nanoTime);
    }

    /** Test-only: defaults for everything but the two bounds the older tests vary. */
    CompositeRevocationChecker(
            Duration timeout, long maxResponseBytes, boolean allowPrivateAddressesForTesting, HostResolver resolver) {
        this(RevocationLimits.withDefaults(timeout, maxResponseBytes), allowPrivateAddressesForTesting, resolver,
                System::nanoTime);
    }

    /**
     * Test-only: {@code allowPrivateAddressesForTesting} disables the SSRF
     * guard so tests can point AIA/CDP URLs at a local HTTP server, {@code
     * resolver} lets a test prove the DNS-rebinding protection itself
     * (resolve once, connect to that exact address -- see {@link
     * RevocationUrlGuard} and {@link PinnedHttpClient}) and {@code nanoClock}
     * makes the total budget deterministic. Never called from production
     * wiring.
     */
    CompositeRevocationChecker(
            RevocationLimits limits, boolean allowPrivateAddressesForTesting, HostResolver resolver,
            LongSupplier nanoClock) {
        Provider bcProvider = new BouncyCastleProvider();
        this.limits = limits;
        this.nanoClock = nanoClock;
        this.ocspClient = new OcspClient(limits, allowPrivateAddressesForTesting, resolver, bcProvider);
        this.crlClient = new CrlClient(limits, allowPrivateAddressesForTesting, resolver);
    }

    @Override
    public RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer) {
        return check(certificate, issuer, newBudget());
    }

    /**
     * Checks every non-anchor certificate of {@code validatedPath} under ONE
     * shared budget (see the class Javadoc) and folds the results as {@link
     * RevocationChecker#checkPath} documents. Stops at the first revoked
     * certificate: the outcome cannot change, and nothing more needs to be
     * contacted.
     */
    @Override
    public RevocationStatus checkPath(List<CertificateInfo> validatedPath) {
        Deadline budget = newBudget();
        List<CertificateInfo> checked = new ArrayList<>(RevocationChecker.nonAnchorCertificates(validatedPath));
        List<RevocationStatus> results = new ArrayList<>(checked.size());
        for (int i = 0; i < checked.size(); i++) {
            CertificateInfo issuer = i + 1 < validatedPath.size() ? validatedPath.get(i + 1) : null;
            RevocationStatus result = check(checked.get(i), issuer, budget);
            results.add(result);
            if (result.state() == RevocationState.REVOKED) {
                return RevocationStatus.aggregate(checked.subList(0, i + 1), results);
            }
        }
        return RevocationStatus.aggregate(checked, results);
    }

    private Deadline newBudget() {
        return Deadline.after(limits.totalTimeout(), nanoClock);
    }

    private RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer, Deadline budget) {
        if (issuer == null) {
            return new RevocationStatus(RevocationState.UNKNOWN, null, "issuer certificate not available");
        }
        if (budget.expired()) {
            return new RevocationStatus(RevocationState.UNKNOWN, null, Deadline.EXHAUSTED_DETAIL);
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

        List<String> ocspUrls = bounded(certificate.ocspUrls());
        List<String> crlUrls = bounded(certificate.crlUrls());
        boolean hasOcsp = !ocspUrls.isEmpty();
        boolean hasCrl = !crlUrls.isEmpty();
        if (!hasOcsp && !hasCrl) {
            return new RevocationStatus(RevocationState.UNKNOWN, null, "no OCSP/CRL URL available for this certificate");
        }

        if (hasOcsp) {
            RevocationStatus ocsp = checkOcspSafely(certificateX509, issuerX509, ocspUrls, budget);
            if (ocsp.state() != RevocationState.UNKNOWN || !hasCrl) {
                return ocsp;
            }
            RevocationStatus crl = checkCrlSafely(certificateX509, issuerX509, crlUrls, budget);
            if (crl.state() != RevocationState.UNKNOWN) {
                return crl;
            }
            return new RevocationStatus(RevocationState.UNKNOWN, crl.source() != null ? crl.source() : ocsp.source(),
                    "OCSP: " + ocsp.detail() + "; CRL: " + crl.detail());
        }

        return checkCrlSafely(certificateX509, issuerX509, crlUrls, budget);
    }

    /** De-duplicated (first occurrence wins) and capped to {@code maxUrlsPerMethod}. */
    private List<String> bounded(List<String> urls) {
        return new LinkedHashSet<>(urls).stream().limit(limits.maxUrlsPerMethod()).toList();
    }

    /**
     * Defense in depth: {@link OcspClient}/{@link CrlClient} already document "never throws",
     * but this adapter must never propagate an exception from them either, whatever its cause.
     */
    private RevocationStatus checkOcspSafely(
            X509Certificate certificate, X509Certificate issuer, List<String> urls, Deadline budget) {
        return safely("OCSP", () -> ocspClient.check(certificate, issuer, urls, budget));
    }

    private RevocationStatus checkCrlSafely(
            X509Certificate certificate, X509Certificate issuer, List<String> urls, Deadline budget) {
        return safely("CRL", () -> crlClient.check(certificate, issuer, urls, budget));
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
