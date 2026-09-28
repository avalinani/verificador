package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Maps a {@code java.security.cert.X509Certificate} (already extracted from
 * the CMS by {@link CmsSignatureVerification}) into the domain's library-free
 * {@link CertificateInfo}, including the OCSP/CRL endpoint URLs from the
 * certificate's Authority Information Access and CRL Distribution Points
 * extensions.
 */
public final class X509CertificateInfoMapper {

    private X509CertificateInfoMapper() {
    }

    /**
     * Public (unlike the rest of this package-private class): reused
     * directly by {@code infrastructure.pki.PkixCertificateChainValidator}
     * to map the trust anchor certificate PKIX actually validated against
     * back into a domain {@link CertificateInfo} -- see {@link
     * com.coam.pdfvalidator.domain.port.CertificateChainValidator#validatedPath}.
     * Both are {@code infrastructure} sub-packages, so this stays an
     * infra-internal reuse; {@code ArchitectureTest} only forbids {@code
     * infrastructure} from depending "upward" on {@code application}/{@code
     * api}.
     */
    public static CertificateInfo toDomain(X509Certificate certificate) {
        try {
            return new CertificateInfo(
                    certificate.getSubjectX500Principal().getName(),
                    certificate.getIssuerX500Principal().getName(),
                    HexFormat.of().formatHex(certificate.getSerialNumber().toByteArray()),
                    certificate.getNotBefore().toInstant(),
                    certificate.getNotAfter().toInstant(),
                    certificate.getSigAlgName(),
                    ocspUrls(certificate),
                    crlUrls(certificate),
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

    /**
     * The result of {@link #toDomainResilient}: the certificates that could
     * be mapped (in the original order, skipping any that failed), and how
     * many did not.
     */
    record MappingResult(List<CertificateInfo> certificates, int failedCount) {
    }

    /**
     * Same as {@link #toDomain(List)}, but a single certificate that cannot
     * be mapped (e.g. it cannot be DER-re-encoded) is skipped rather than
     * aborting the whole chain: a CMS signature that verified must not be
     * reported as an invalid signature merely because one certificate's
     * data could not be extracted. The caller is expected to surface {@link
     * MappingResult#failedCount()} as an anomaly note rather than silently
     * dropping certificates.
     */
    static MappingResult toDomainResilient(List<X509Certificate> certificates) {
        List<CertificateInfo> mapped = new ArrayList<>(certificates.size());
        int failed = 0;
        for (X509Certificate certificate : certificates) {
            try {
                mapped.add(toDomain(certificate));
            } catch (RuntimeException e) {
                failed++;
            }
        }
        return new MappingResult(List.copyOf(mapped), failed);
    }

    private static List<String> ocspUrls(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extensionValue == null) {
            return List.of();
        }
        try {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(innerDer(extensionValue));
            List<String> urls = new ArrayList<>();
            for (AccessDescription accessDescription : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(accessDescription.getAccessMethod())) {
                    uriOf(accessDescription.getAccessLocation()).ifPresent(urls::add);
                }
            }
            return List.copyOf(urls);
        } catch (IOException | RuntimeException e) {
            // A malformed AIA extension does not invalidate the whole
            // certificate: simply report no OCSP URLs for it.
            return List.of();
        }
    }

    private static List<String> crlUrls(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return List.of();
        }
        try {
            CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(innerDer(extensionValue));
            List<String> urls = new ArrayList<>();
            for (DistributionPoint distributionPoint : crlDistPoint.getDistributionPoints()) {
                DistributionPointName name = distributionPoint.getDistributionPoint();
                if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                    GeneralNames generalNames = GeneralNames.getInstance(name.getName());
                    for (GeneralName generalName : generalNames.getNames()) {
                        uriOf(generalName).ifPresent(urls::add);
                    }
                }
            }
            return List.copyOf(urls);
        } catch (IOException | RuntimeException e) {
            return List.of();
        }
    }

    /**
     * {@code X509Certificate#getExtensionValue} returns the DER encoding of
     * an {@code OCTET STRING} that itself wraps the extension's real DER
     * value; this unwraps that one layer.
     */
    private static ASN1Primitive innerDer(byte[] extensionValue) throws IOException {
        ASN1OctetString octetString = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extensionValue));
        return ASN1Primitive.fromByteArray(octetString.getOctets());
    }

    private static Optional<String> uriOf(GeneralName name) {
        if (name.getTagNo() == GeneralName.uniformResourceIdentifier && name.getName() instanceof ASN1String string) {
            return Optional.of(string.getString());
        }
        return Optional.empty();
    }
}
