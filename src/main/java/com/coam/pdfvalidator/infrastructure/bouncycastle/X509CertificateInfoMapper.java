package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.CertificateInfo;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Maps a {@code java.security.cert.X509Certificate} (already extracted from
 * the CMS by {@link CmsSignatureVerification}) into the domain's library-free
 * {@link CertificateInfo}.
 *
 * <p>OCSP/CRL endpoint extraction is added separately (see the follow-up
 * commit extending this class): for now {@code ocspUrls}/{@code crlUrls}
 * always report empty.
 */
final class X509CertificateInfoMapper {

    private X509CertificateInfoMapper() {
    }

    static CertificateInfo toDomain(X509Certificate certificate) {
        try {
            return new CertificateInfo(
                    certificate.getSubjectX500Principal().getName(),
                    certificate.getIssuerX500Principal().getName(),
                    HexFormat.of().formatHex(certificate.getSerialNumber().toByteArray()),
                    certificate.getNotBefore().toInstant(),
                    certificate.getNotAfter().toInstant(),
                    certificate.getSigAlgName(),
                    List.of(),
                    List.of(),
                    certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Failed to DER-encode a certificate extracted from a CMS signature", e);
        }
    }

    static List<CertificateInfo> toDomain(List<X509Certificate> certificates) {
        List<CertificateInfo> result = new ArrayList<>(certificates.size());
        for (X509Certificate certificate : certificates) {
            result.add(toDomain(certificate));
        }
        return List.copyOf(result);
    }
}
