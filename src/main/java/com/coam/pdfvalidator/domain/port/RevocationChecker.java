package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.RevocationStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Checks whether a certificate has been revoked (OCSP first, CRL fallback,
 * per the use case's configured policy). Optional feature: callers should
 * fall back to {@link RevocationStatus#notChecked()} when revocation
 * checking is disabled, and to {@code UNKNOWN} on timeout/failure.
 */
public interface RevocationChecker {

    RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer);

    /**
     * Checks every non-anchor certificate of a validated certification path
     * (signer first, trust anchor last) against its issuer and folds the
     * results with {@link RevocationStatus#aggregate}: any revoked
     * certificate makes the path revoked, any inconclusive one makes it
     * inconclusive, only an all-good path is good. The trust anchor itself is
     * never checked (there is nobody above it to revoke it; its trust is a
     * local configuration decision). A path made only of the anchor is
     * checked as a lone certificate without issuer.
     *
     * <p>Implementations that bound the total effort of one signature
     * (a shared deadline) override this; the default just calls {@link
     * #check} once per certificate.
     */
    default RevocationStatus checkPath(List<CertificateInfo> validatedPath) {
        List<CertificateInfo> checked = nonAnchorCertificates(validatedPath);
        List<RevocationStatus> results = new ArrayList<>(checked.size());
        for (int i = 0; i < checked.size(); i++) {
            CertificateInfo issuer = i + 1 < validatedPath.size() ? validatedPath.get(i + 1) : null;
            results.add(check(checked.get(i), issuer));
        }
        return RevocationStatus.aggregate(checked, results);
    }

    /** The certificates of {@code validatedPath} that revocation applies to: all but the trust anchor (last). */
    static List<CertificateInfo> nonAnchorCertificates(List<CertificateInfo> validatedPath) {
        return validatedPath.size() <= 1 ? validatedPath : validatedPath.subList(0, validatedPath.size() - 1);
    }
}
