package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.fixtures.TestPki;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link X509CertificateInfoMapper} maps a real certificate's OCSP/CRL
 * extensions to URL lists, catching a malformed extension internally
 * ({@code IOException | RuntimeException}) so it yields an empty list for
 * that one extension rather than failing the whole certificate mapping.
 * These tests exercise that resilience path directly with a certificate
 * double whose extension bytes are deliberately not valid DER, since a real,
 * honestly-issued certificate never carries a malformed extension.
 */
class X509CertificateInfoMapperTest {

    @Test
    void aRealCertificatesOcspAndCrlUrlsAreMappedWithoutIssue() {
        X509Certificate certificate = TestPki.issueSigningIdentity().endEntityCertificate();

        CertificateInfo info = X509CertificateInfoMapper.toDomain(certificate);

        assertThat(info.subject()).isNotBlank();
        // TestPki's end-entity certificate declares AIA/CRLDP extensions (see T04); a well-formed
        // extension must be readable without needing the malformed-extension fallback below.
        assertThat(info.ocspUrls()).isNotEmpty();
        assertThat(info.crlUrls()).isNotEmpty();
    }

    /**
     * T11f: a real signer's subject can declare {@code emailAddress} (OID
     * 1.2.840.113549.1.9.1). The JDK's own {@code X500Principal} RFC 2253
     * formatting doesn't know that OID and falls back to a hex-encoded
     * {@code "#16<hex>"} dump of the raw DER value -- unreadable in the web
     * UI. The mapper must instead produce a human-readable DN (decoded
     * string value, {@code E=...} label) and expose the subject's {@code CN}
     * separately via {@link CertificateInfo#commonName()}.
     */
    @Test
    void aReadableSubjectDecodesTheEmailAddressAttributeAndExposesTheCommonNameSeparately() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "ES");
        builder.addRDN(BCStyle.O, "COAM");
        builder.addRDN(BCStyle.OU, "Certificado de pruebas T11f");
        builder.addRDN(BCStyle.SERIALNUMBER, "12345678A");
        builder.addRDN(BCStyle.GIVENNAME, "MARIA");
        builder.addRDN(BCStyle.SURNAME, "GARCIA LOPEZ");
        builder.addRDN(BCStyle.E, "maria.garcia@example.org");
        builder.addRDN(BCStyle.CN, "GARCIA LOPEZ MARIA - 12345678A");
        X500Name subjectWithEmail = builder.build();

        X509Certificate certificate =
                TestPki.issueSigningIdentityWithSubject(subjectWithEmail).endEntityCertificate();

        CertificateInfo info = X509CertificateInfoMapper.toDomain(certificate);

        assertThat(info.subject()).doesNotContain("#16");
        assertThat(info.subject()).containsAnyOf(
                "E=maria.garcia@example.org", "EMAILADDRESS=maria.garcia@example.org");
        assertThat(info.commonName()).isEqualTo("GARCIA LOPEZ MARIA - 12345678A");
    }

    @Test
    void aMalformedAuthorityInfoAccessExtensionYieldsNoOcspUrlsWithoutThrowing() {
        X509Certificate certificate = certificateWithExtension(Extension.authorityInfoAccess.getId());

        CertificateInfo info = X509CertificateInfoMapper.toDomain(certificate);

        assertThat(info.ocspUrls()).isEmpty();
    }

    @Test
    void aMalformedCrlDistributionPointsExtensionYieldsNoCrlUrlsWithoutThrowing() {
        X509Certificate certificate = certificateWithExtension(Extension.cRLDistributionPoints.getId());

        CertificateInfo info = X509CertificateInfoMapper.toDomain(certificate);

        assertThat(info.crlUrls()).isEmpty();
    }

    /**
     * A certificate double with plausible core fields but a deliberately
     * malformed value (not valid DER at all, let alone the extension's own
     * ASN.1 structure) for the extension named by {@code malformedExtensionOid}.
     * All other extension lookups return {@code null} (Mockito's default for
     * an unstubbed {@code byte[]}-returning method), i.e. "extension absent".
     */
    private static X509Certificate certificateWithExtension(String malformedExtensionOid) {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal("CN=Malformed Extension Test"));
        when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=Malformed Extension Test"));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.TEN);
        when(certificate.getNotBefore()).thenReturn(Date.from(Instant.EPOCH));
        when(certificate.getNotAfter()).thenReturn(Date.from(Instant.EPOCH.plusSeconds(3600)));
        when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
        try {
            when(certificate.getEncoded()).thenReturn(new byte[] {0x30, 0x03, 0x02, 0x01, 0x00});
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new AssertionError(e);
        }
        // Not a valid ASN.1 OCTET STRING at all: ASN1Primitive.fromByteArray must throw IOException,
        // which the mapper's per-extension try/catch turns into an empty URL list.
        when(certificate.getExtensionValue(malformedExtensionOid)).thenReturn(new byte[] {0x00, 0x01, 0x02});
        return certificate;
    }
}
