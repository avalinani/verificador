package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.RevocationStatus;

/**
 * Checks whether a certificate has been revoked (OCSP first, CRL fallback,
 * per the use case's configured policy). Optional feature: callers should
 * fall back to {@link RevocationStatus#notChecked()} when revocation
 * checking is disabled, and to {@code UNKNOWN} on timeout/failure.
 */
public interface RevocationChecker {

    RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer);
}
