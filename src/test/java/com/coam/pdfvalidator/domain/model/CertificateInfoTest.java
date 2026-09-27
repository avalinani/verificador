package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateInfoTest {

    private static CertificateInfo certificateValidFor(Instant notBefore, Instant notAfter) {
        return new CertificateInfo(
                "CN=Test Signer",
                "CN=Test Root CA",
                "01",
                notBefore,
                notAfter,
                "SHA256withRSA",
                List.of("http://ocsp.example.org"),
                List.of("http://crl.example.org"),
                new byte[] {1, 2, 3});
    }

    @Test
    void isValidAtReturnsTrueWithinTheValidityWindow() {
        Instant now = Instant.now();
        CertificateInfo certificate = certificateValidFor(now.minus(1, ChronoUnit.DAYS), now.plus(1, ChronoUnit.DAYS));

        assertThat(certificate.isValidAt(now)).isTrue();
    }

    @Test
    void isValidAtReturnsFalseBeforeNotBefore() {
        Instant now = Instant.now();
        CertificateInfo certificate = certificateValidFor(now.plus(1, ChronoUnit.DAYS), now.plus(2, ChronoUnit.DAYS));

        assertThat(certificate.isValidAt(now)).isFalse();
    }

    @Test
    void isValidAtReturnsFalseAfterNotAfter() {
        Instant now = Instant.now();
        CertificateInfo certificate = certificateValidFor(now.minus(2, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS));

        assertThat(certificate.isValidAt(now)).isFalse();
    }

    @Test
    void mutatingTheInputOcspUrlsListDoesNotAffectTheRecord() {
        Instant now = Instant.now();
        List<String> mutableOcspUrls = new ArrayList<>(List.of("http://ocsp.example.org"));
        CertificateInfo certificate = new CertificateInfo(
                "CN=Test Signer",
                "CN=Test Root CA",
                "01",
                now.minus(1, ChronoUnit.DAYS),
                now.plus(1, ChronoUnit.DAYS),
                "SHA256withRSA",
                mutableOcspUrls,
                List.of(),
                new byte[] {1, 2, 3});

        mutableOcspUrls.add("http://another-ocsp.example.org");

        assertThat(certificate.ocspUrls()).containsExactly("http://ocsp.example.org");
    }

    @Test
    void mutatingTheInputEncodedBytesDoesNotAffectTheRecord() {
        Instant now = Instant.now();
        byte[] mutableEncoded = {1, 2, 3};
        CertificateInfo certificate = new CertificateInfo(
                "CN=Test Signer",
                "CN=Test Root CA",
                "01",
                now.minus(1, ChronoUnit.DAYS),
                now.plus(1, ChronoUnit.DAYS),
                "SHA256withRSA",
                List.of(),
                List.of(),
                mutableEncoded);

        mutableEncoded[0] = (byte) 99;

        assertThat(certificate.encoded()).containsExactly(1, 2, 3);
    }

    @Test
    void mutatingTheReturnedEncodedBytesDoesNotAffectTheRecord() {
        Instant now = Instant.now();
        CertificateInfo certificate = certificateValidFor(now.minus(1, ChronoUnit.DAYS), now.plus(1, ChronoUnit.DAYS));

        certificate.encoded()[0] = (byte) 42;

        assertThat(certificate.encoded()).containsExactly(1, 2, 3);
    }

    @Test
    void twoCertificatesWithTheSameEncodedBytesAreEqual() {
        Instant notBefore = Instant.now().minus(1, ChronoUnit.DAYS);
        Instant notAfter = Instant.now().plus(1, ChronoUnit.DAYS);
        CertificateInfo first = certificateValidFor(notBefore, notAfter);
        CertificateInfo second = certificateValidFor(notBefore, notAfter);

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void certificatesWithDifferentEncodedBytesAreNotEqual() {
        Instant notBefore = Instant.now().minus(1, ChronoUnit.DAYS);
        Instant notAfter = Instant.now().plus(1, ChronoUnit.DAYS);
        CertificateInfo first = certificateValidFor(notBefore, notAfter);
        CertificateInfo second = new CertificateInfo(
                "CN=Test Signer",
                "CN=Test Root CA",
                "01",
                notBefore,
                notAfter,
                "SHA256withRSA",
                List.of("http://ocsp.example.org"),
                List.of("http://crl.example.org"),
                new byte[] {9, 9, 9});

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void toStringDoesNotDumpTheFullEncodedByteArray() {
        CertificateInfo certificate = certificateValidFor(Instant.now().minus(1, ChronoUnit.DAYS), Instant.now().plus(1, ChronoUnit.DAYS));

        String text = certificate.toString();

        assertThat(text).contains("CN=Test Signer").contains("3 bytes");
        assertThat(text).doesNotContain("[B@");
    }
}
