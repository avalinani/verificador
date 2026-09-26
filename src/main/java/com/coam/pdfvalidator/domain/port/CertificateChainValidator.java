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
}
