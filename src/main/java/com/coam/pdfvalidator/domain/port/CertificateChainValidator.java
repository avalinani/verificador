package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;

import java.time.Instant;
import java.util.List;

/**
 * Validates a certificate chain (PKIX path building/validation) against a
 * configured trust store. Takes {@link CertificateInfo}, whose
 * {@code encoded()} DER bytes let an infrastructure adapter rebuild real
 * {@code java.security.cert.X509Certificate} instances, so the domain never
 * depends on a certificate library.
 */
public interface CertificateChainValidator {

    ChainStatus validate(List<CertificateInfo> chain, Instant validationTime);

    /**
     * The certificates actually used to reach {@link ChainStatus#TRUSTED}
     * for the same arguments (signer-first, ending at the trust anchor that
     * closed the path) -- used so revocation checking (T10) only ever
     * sources OCSP/CRL URLs and an issuer from certificates a real trust
     * decision was made about, never from an extra or unrelated certificate
     * a hostile CMS {@code SignedData} might also embed alongside a
     * genuine, otherwise-trusted chain.
     *
     * <p>Callers must only rely on this when {@link #validate} itself
     * returned {@link ChainStatus#TRUSTED} for the same {@code chain}/
     * {@code validationTime} -- {@code AnalyzePdfUseCase} enforces exactly
     * that gate before ever calling this method. The default implementation
     * (used by simple test fakes with no real PKIX path-building of their
     * own) returns {@code chain} unchanged, which is a safe stand-in exactly
     * because those fakes have no "extra embedded certificate" concern to
     * begin with.
     */
    default List<CertificateInfo> validatedPath(List<CertificateInfo> chain, Instant validationTime) {
        return chain;
    }
}
