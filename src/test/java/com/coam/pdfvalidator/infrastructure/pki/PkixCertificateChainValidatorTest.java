package com.coam.pdfvalidator.infrastructure.pki;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.fixtures.TestPki;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link PkixCertificateChainValidator} against real, cryptographically
 * valid chains built by {@link TestPki} -- no revocation checking is
 * exercised here (that is T10), only path building/trust/validity.
 */
class PkixCertificateChainValidatorTest {

    @Test
    void aChainToATrustedRootIsTrusted() {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.rootCertificate()));

        ChainStatus status = validator.validate(toCertificateInfos(identity.chain()), Instant.now());

        assertThat(status).isEqualTo(ChainStatus.TRUSTED);
    }

    @Test
    void aChainToARootNotInTheTrustStoreIsUntrusted() {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        // A trust store that only knows about an unrelated root: the presented
        // chain is structurally complete (it does reach a self-signed
        // certificate), but that root is not a configured anchor.
        TestPki.IssuedIdentity unrelated = TestPki.issueSigningIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(unrelated.rootCertificate()));

        ChainStatus status = validator.validate(toCertificateInfos(identity.chain()), Instant.now());

        assertThat(status).isEqualTo(ChainStatus.UNTRUSTED_ROOT);
    }

    @Test
    void aChainMissingItsIntermediateCertificateIsIncomplete() {
        TestPki.ThreeTierIdentity identity = TestPki.issueThreeTierIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.rootCertificate()));

        // The end-entity certificate was issued by the INTERMEDIATE, not the
        // root directly: presenting [ee, root] (skipping the intermediate)
        // means the end-entity's signature does not verify against the
        // root's public key, so the chain never reaches a self-signed
        // certificate through a genuine signature link.
        List<CertificateInfo> incompleteChain =
                toCertificateInfos(List.of(identity.endEntityCertificate(), identity.rootCertificate()));

        ChainStatus status = validator.validate(incompleteChain, Instant.now());

        assertThat(status).isEqualTo(ChainStatus.INCOMPLETE_CHAIN);
    }

    @Test
    void aChainValidatedAfterTheEndEntityCertificateExpiredIsExpired() {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.rootCertificate()));

        // issueSigningIdentity()'s certificates are valid for ~365 days from
        // issuance; validating well past that must report EXPIRED regardless
        // of trust configuration.
        Instant validationTime = Instant.now().plus(400, ChronoUnit.DAYS);

        ChainStatus status = validator.validate(toCertificateInfos(identity.chain()), validationTime);

        assertThat(status).isEqualTo(ChainStatus.EXPIRED);
    }

    @Test
    void anEmptyChainIsNotChecked() {
        PkixCertificateChainValidator validator = new PkixCertificateChainValidator(TrustAnchorProvider.of());

        ChainStatus status = validator.validate(List.of(), Instant.now());

        assertThat(status).isEqualTo(ChainStatus.NOT_CHECKED);
    }

    private static List<CertificateInfo> toCertificateInfos(List<X509Certificate> certificates) {
        return certificates.stream().map(PkixCertificateChainValidatorTest::toCertificateInfo).toList();
    }

    private static CertificateInfo toCertificateInfo(X509Certificate certificate) {
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
            throw new IllegalStateException(e);
        }
    }
}
