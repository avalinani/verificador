package com.coam.pdfvalidator.infrastructure.pki;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.infrastructure.bouncycastle.X509CertificateInfoMapper;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

    /**
     * T09c follow-up (Camerfirma trust anchor): the EU Trusted Lists model
     * publishes the qualified ISSUING CA as the trust anchor, not
     * necessarily its (possibly unpublished) root -- e.g. Spain's TSL lists
     * "AC CAMERFIRMA FOR LEGAL PERSONS - 2016" but not its own issuer,
     * "CHAMBERS OF COMMERCE ROOT - 2016". A {@link
     * java.security.cert.TrustAnchor} configured with such a non-self-signed
     * certificate must still be usable: the JDK's own PKIX {@link
     * java.security.cert.CertPathBuilder} treats any anchor certificate as a
     * valid path terminus regardless of whether that certificate is itself
     * self-signed, so a chain presented as {@code [ee, intermediate]} (the
     * real root omitted, exactly as it would be when only the intermediate
     * is configured as a trust anchor) must resolve to {@code TRUSTED}.
     */
    @Test
    void aChainAnchoredAtANonSelfSignedIntermediateIsTrusted() {
        TestPki.ThreeTierIdentity identity = TestPki.issueThreeTierIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.intermediateCertificate()));

        List<CertificateInfo> chain =
                toCertificateInfos(List.of(identity.endEntityCertificate(), identity.intermediateCertificate()));

        ChainStatus status = validator.validate(chain, Instant.now());

        assertThat(status).isEqualTo(ChainStatus.TRUSTED);
    }

    /**
     * T09d: the real-world case that motivated bundling FNMT's qualified
     * issuing CAs as trust anchors. Unlike {@link
     * #aChainAnchoredAtANonSelfSignedIntermediateIsTrusted}, which presents
     * {@code [ee, intermediate]} (the intermediate embedded in the CMS,
     * just not the root), a real FNMT-signed PDF's CMS embeds <em>only</em>
     * the end-entity certificate -- the issuing CA is never embedded at
     * all. The presented chain here is {@code [ee]} alone; the JDK's PKIX
     * {@link java.security.cert.CertPathBuilder} must still resolve it to
     * {@code TRUSTED} once the (non-self-signed) intermediate itself is a
     * configured anchor, since it needs no certificate for the anchor in
     * its {@code CertStore} -- the anchor is supplied separately from the
     * presented chain.
     */
    @Test
    void aChainOmittingAnIntermediateNotEmbeddedInTheCmsIsTrustedWhenThatIntermediateIsTheAnchor() {
        TestPki.ThreeTierIdentity identity = TestPki.issueThreeTierIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.intermediateCertificate()));

        List<CertificateInfo> chainWithOnlyTheEndEntity =
                toCertificateInfos(List.of(identity.endEntityCertificate()));

        ChainStatus status = validator.validate(chainWithOnlyTheEndEntity, Instant.now());

        assertThat(status).isEqualTo(ChainStatus.TRUSTED);
    }

    @Test
    void anEmptyChainIsNotChecked() {
        PkixCertificateChainValidator validator = new PkixCertificateChainValidator(TrustAnchorProvider.of());

        ChainStatus status = validator.validate(List.of(), Instant.now());

        assertThat(status).isEqualTo(ChainStatus.NOT_CHECKED);
    }

    /**
     * T06b follow-up: a {@link CertificateInfo#encoded()} that does not parse
     * back into an {@code X509Certificate} (garbage DER, or DER for some
     * other ASN.1 structure entirely) previously escaped as an unchecked
     * {@code IllegalStateException} from {@code toX509Certificates}. A single
     * hostile/corrupt certificate must never abort the whole analysis: it is
     * reported as {@link ChainStatus#INCOMPLETE_CHAIN} instead (an
     * unparseable certificate contributes no verifiable link, so the chain
     * can never be considered structurally complete), never thrown.
     */
    @Test
    void aChainContainingAnUnparseableCertificateIsIncompleteNotThrown() {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.rootCertificate()));

        CertificateInfo validEndEntity = toCertificateInfo(identity.chain().get(0));
        CertificateInfo garbage = new CertificateInfo(
                "CN=garbage", "garbage", "CN=garbage", "00", Instant.EPOCH, Instant.EPOCH.plusSeconds(3600),
                "SHA256withRSA", List.of(), List.of(), new byte[] {1, 2, 3, 4, 5});

        ChainStatus status = validator.validate(List.of(validEndEntity, garbage), Instant.now());

        assertThat(status).isEqualTo(ChainStatus.INCOMPLETE_CHAIN);
    }

    // ---- validatedPath (T10 security decision: revocation only ever
    // sources its issuer from the certificates PKIX itself trusted) ----

    @Test
    void validatedPathReturnsTheOriginalCertificateInfosWhenTheWholeChainWasPresented() {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.rootCertificate()));
        List<CertificateInfo> chain = toCertificateInfos(identity.chain());

        List<CertificateInfo> validatedPath = validator.validatedPath(chain, Instant.now());

        assertThat(validatedPath).isEqualTo(chain);
    }

    /**
     * The T09d FNMT scenario: only the end-entity certificate is presented,
     * trusted because its issuer is directly configured as the anchor. The
     * anchor certificate itself is not part of {@code chain}, so it must be
     * mapped fresh -- {@code validatedPath} must still surface it (by its
     * real subject/encoded bytes), because {@code AnalyzePdfUseCase} needs
     * an actual issuer certificate to check revocation against.
     */
    @Test
    void validatedPathAppendsTheAnchorCertificateWhenOnlyTheEndEntityWasPresented() throws CertificateEncodingException {
        TestPki.ThreeTierIdentity identity = TestPki.issueThreeTierIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.intermediateCertificate()));
        List<CertificateInfo> chain = toCertificateInfos(List.of(identity.endEntityCertificate()));

        List<CertificateInfo> validatedPath = validator.validatedPath(chain, Instant.now());

        assertThat(validatedPath).hasSize(2);
        assertThat(validatedPath.get(0)).isEqualTo(chain.get(0));
        assertThat(validatedPath.get(1).encoded()).isEqualTo(identity.intermediateCertificate().getEncoded());
    }

    /**
     * The core SSRF-relevant guarantee: an extra certificate the presented
     * chain also carries (as a hostile CMS {@code SignedData} could embed
     * alongside a genuine path) must never appear in {@code validatedPath},
     * even though it was part of the {@code CertStore} handed to PKIX --
     * only the certificates on the actually-built path do.
     */
    @Test
    void validatedPathExcludesAnUnrelatedExtraCertificatePresentedAlongsideAGenuinePath()
            throws CertificateEncodingException {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        TestPki.IssuedIdentity unrelated = TestPki.issueSigningIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(identity.rootCertificate()));

        CertificateInfo unrelatedExtra = toCertificateInfo(unrelated.endEntityCertificate());
        List<CertificateInfo> chainWithExtraCertificate = List.of(
                toCertificateInfo(identity.endEntityCertificate()), unrelatedExtra,
                toCertificateInfo(identity.rootCertificate()));

        List<CertificateInfo> validatedPath = validator.validatedPath(chainWithExtraCertificate, Instant.now());

        assertThat(validatedPath).hasSize(2).doesNotContain(unrelatedExtra);
        assertThat(validatedPath.get(0).encoded()).isEqualTo(identity.endEntityCertificate().getEncoded());
        assertThat(validatedPath.get(1).encoded()).isEqualTo(identity.rootCertificate().getEncoded());
    }

    @Test
    void validatedPathIsEmptyForAnEmptyChain() {
        PkixCertificateChainValidator validator = new PkixCertificateChainValidator(TrustAnchorProvider.of());

        assertThat(validator.validatedPath(List.of(), Instant.now())).isEmpty();
    }

    @Test
    void validatedPathIsEmptyWhenTheChainDoesNotBuildATrustedPath() {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        TestPki.IssuedIdentity unrelated = TestPki.issueSigningIdentity();
        PkixCertificateChainValidator validator =
                new PkixCertificateChainValidator(TrustAnchorProvider.of(unrelated.rootCertificate()));

        List<CertificateInfo> validatedPath =
                validator.validatedPath(toCertificateInfos(identity.chain()), Instant.now());

        assertThat(validatedPath).isEmpty();
    }

    private static List<CertificateInfo> toCertificateInfos(List<X509Certificate> certificates) {
        return certificates.stream().map(PkixCertificateChainValidatorTest::toCertificateInfo).toList();
    }

    /**
     * Uses the production mapper (not a hand-rolled copy) so the DN format the
     * validator sees in these tests cannot drift from what production emits.
     */
    private static CertificateInfo toCertificateInfo(X509Certificate certificate) {
        return X509CertificateInfoMapper.toDomain(certificate);
    }
}
