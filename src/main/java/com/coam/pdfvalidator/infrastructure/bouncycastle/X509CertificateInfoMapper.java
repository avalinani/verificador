package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import javax.security.auth.x500.X500Principal;
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
            ReadableSubject subject = readableSubject(certificate.getSubjectX500Principal());
            return new CertificateInfo(
                    subject.dn(),
                    subject.commonName(),
                    readableDn(certificate.getIssuerX500Principal()),
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

    /** {@link #readableDn}'s formatted DN, plus the subject's own {@code CN} attribute (or {@code null}). */
    private record ReadableSubject(String dn, String commonName) {
    }

    /**
     * A human-readable rendering of {@code principal}, decoding every
     * attribute Bouncy Castle's {@link BCStyle} recognizes by OID --
     * including {@code emailAddress} (OID 1.2.840.113549.1.9.1, labeled
     * {@code E}), {@code organizationIdentifier}, {@code SERIALNUMBER},
     * {@code GIVENNAME}/{@code SURNAME}, {@code T} (title), etc. -- instead
     * of the JDK's own {@code X500Principal#getName()} RFC 2253 rendering,
     * which falls back to a {@code "#16<hex>"} dump of the raw DER value for
     * any attribute type it does not itself recognize (T11f: this made
     * emailAddress, a very common attribute on Spanish qualified
     * certificates, unreadable in the web UI). An OID neither style
     * recognizes still renders as {@code <oid>=<value>} with the value
     * decoded when it is a string type -- Bouncy Castle's own fallback,
     * hex only as a last resort for a non-string-typed value.
     *
     * <p>Falls back to {@code principal.getName()} if the principal's own
     * DER encoding cannot be re-parsed into an {@link X500Name} at all
     * (defensive: every real {@code X509Certificate}'s principal is valid
     * DER by construction, so this path is not expected to be reachable in
     * practice).
     */
    private static String readableDn(X500Principal principal) {
        try {
            return BCStyle.INSTANCE.toString(x500NameOf(principal));
        } catch (RuntimeException e) {
            return principal.getName();
        }
    }

    /** Same as {@link #readableDn}, but also extracts the subject's own {@code CN} attribute. */
    private static ReadableSubject readableSubject(X500Principal principal) {
        try {
            X500Name name = x500NameOf(principal);
            return new ReadableSubject(BCStyle.INSTANCE.toString(name), commonNameOf(name));
        } catch (RuntimeException e) {
            return new ReadableSubject(principal.getName(), null);
        }
    }

    /** The first {@code CN} RDN's decoded string value, or {@code null} if {@code name} has none. */
    private static String commonNameOf(X500Name name) {
        RDN[] commonNameRdns = name.getRDNs(BCStyle.CN);
        if (commonNameRdns.length == 0) {
            return null;
        }
        return IETFUtils.valueToString(commonNameRdns[0].getFirst().getValue());
    }

    private static X500Name x500NameOf(X500Principal principal) {
        return X500Name.getInstance(ASN1Sequence.getInstance(principal.getEncoded()));
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
