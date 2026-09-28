package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.fixtures.TestHttpServer;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.fixtures.TestRevocationResponder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CompositeRevocationChecker}: OCSP-first, CRL-fallback orchestration
 * against real, in-process OCSP/CRL servers -- the individual client
 * behaviors themselves are covered by {@link OcspClientTest}/{@link
 * CrlClientTest}.
 */
class CompositeRevocationCheckerTest {

    private TestHttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        server = TestHttpServer.start();
    }

    @AfterEach
    void stopServer() {
        server.close();
    }

    private CompositeRevocationChecker checker() {
        // allowPrivateAddressesForTesting=true: this test's server is bound to 127.0.0.1.
        return new CompositeRevocationChecker(
                Duration.ofSeconds(2), 10 * 1024 * 1024, true, HostResolver.systemDefault());
    }

    @Test
    void ocspGoodIsReturnedWithoutEverTryingCrl() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(server.baseUrl() + "/ocsp", "http://crl.invalid/should-not-be-tried.crl");
        server.respondDynamically("/ocsp", "application/ocsp-response",
                requestBytes -> TestRevocationResponder.ocspResponse(
                        requestBytes, identity.issuerCertificate(), identity.issuerPrivateKey(),
                        TestRevocationResponder.OcspOutcome.GOOD));

        RevocationStatus status = checker().check(toDomain(identity.signerCertificate()), toDomain(identity.issuerCertificate()));

        assertThat(status.state()).isEqualTo(RevocationState.GOOD);
        assertThat(status.source()).contains("/ocsp");
    }

    /** OCSP unreachable (nothing listening) falls back to a working CRL. */
    @Test
    void fallsBackToCrlWhenOcspIsUnreachable() throws Exception {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(
                "http://127.0.0.1:1/unreachable-ocsp", server.baseUrl() + "/crl");
        byte[] crl = TestRevocationResponder.crl(
                identity.issuerCertificate(), identity.issuerPrivateKey(), List.of(), Instant.now().plusSeconds(3600));
        server.respond("/crl", 200, "application/pkix-crl", crl);

        RevocationStatus status = checker().check(toDomain(identity.signerCertificate()), toDomain(identity.issuerCertificate()));

        assertThat(status.state()).isEqualTo(RevocationState.GOOD);
        assertThat(status.source()).contains("/crl");
    }

    @Test
    void bothOcspAndCrlInconclusiveIsUnknownWithACombinedReason() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(
                "http://127.0.0.1:1/unreachable-ocsp", "http://127.0.0.1:1/unreachable-crl");

        RevocationStatus status = checker().check(toDomain(identity.signerCertificate()), toDomain(identity.issuerCertificate()));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("OCSP:").contains("CRL:");
    }

    @Test
    void noOcspOrCrlUrlIsUnknown() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);

        RevocationStatus status = checker().check(toDomain(identity.signerCertificate()), toDomain(identity.issuerCertificate()));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("no OCSP/CRL URL");
    }

    @Test
    void aNullIssuerIsUnknownWithoutContactingAnything() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(server.baseUrl() + "/ocsp", server.baseUrl() + "/crl");

        RevocationStatus status = checker().check(toDomain(identity.signerCertificate()), null);

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("issuer certificate not available");
    }

    /**
     * Reuses this project's own {@code X509CertificateInfoMapper} (the same
     * mapper {@code BcSignatureVerifier} uses in production) instead of
     * duplicating AIA/CDP-extraction logic in a test -- it is public
     * exactly for this kind of infra-internal reuse, see its own Javadoc.
     */
    private static CertificateInfo toDomain(X509Certificate certificate) {
        return com.coam.pdfvalidator.infrastructure.bouncycastle.X509CertificateInfoMapper.toDomain(certificate);
    }
}
