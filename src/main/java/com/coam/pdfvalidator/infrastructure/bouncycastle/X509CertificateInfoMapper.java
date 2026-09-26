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
