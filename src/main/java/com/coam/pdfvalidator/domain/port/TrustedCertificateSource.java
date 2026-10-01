package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.CertificateInfo;

import java.util.List;

/**
 * The certificates the validator is configured to trust (its trust anchors), exposed read-only to adapters that
 * need to look a certificate up by identity -- today the signature verifier, which finds a timestamp authority
 * certificate that the RFC 3161 token itself does not carry. It is a lookup source only: being listed here never
 * makes anything trusted by itself; the trust decision stays with {@link CertificateChainValidator}.
 */
public interface TrustedCertificateSource {

    /** The configured trust anchor certificates; empty when none are configured. */
    List<CertificateInfo> trustedCertificates();

    /** A source with no certificates. */
    static TrustedCertificateSource none() {
        return List::of;
    }
}
