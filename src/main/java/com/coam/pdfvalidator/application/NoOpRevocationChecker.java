package com.coam.pdfvalidator.application;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.port.RevocationChecker;

/**
 * Temporary stand-in for a real {@link RevocationChecker} (OCSP/CRL, T10):
 * always reports {@link RevocationState#NOT_CHECKED} with a detail
 * explaining why, rather than silently pretending revocation was checked.
 *
 * <p>{@link AnalyzePdfUseCase} only calls this when {@link
 * AnalysisOptions#checkRevocation()} is {@code true} -- when it is {@code
 * false}, the use case uses {@link RevocationStatus#notChecked()} directly
 * (no detail), so "revocation checking was disabled" and "revocation
 * checking was requested but is not implemented yet" stay distinguishable if
 * that detail is ever surfaced to a caller.
 */
public final class NoOpRevocationChecker implements RevocationChecker {

    static final String DETAIL = "revocation checking not available yet";

    @Override
    public RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer) {
        return new RevocationStatus(RevocationState.NOT_CHECKED, null, DETAIL);
    }
}
