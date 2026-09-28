package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.fixtures.TestHttpServer;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.fixtures.TestRevocationResponder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** {@link CrlClient} against a real, in-process HTTP server serving real, cryptographically signed CRLs. */
class CrlClientTest {

    private TestHttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        server = TestHttpServer.start();
    }

    @AfterEach
    void stopServer() {
        server.close();
    }

    private CrlClient client(Duration timeout) {
        return client(timeout, HostResolver.systemDefault());
    }

    private CrlClient client(Duration timeout, HostResolver resolver) {
        // allowPrivateAddresses=true: this test's server is bound to 127.0.0.1.
        return new CrlClient(timeout, 10 * 1024 * 1024, true, resolver);
    }

    @Test
    void aGoodCrlIsReportedAsGood() throws Exception {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(null, server.baseUrl() + "/crl");
        byte[] crl = TestRevocationResponder.crl(
                identity.issuerCertificate(), identity.issuerPrivateKey(), List.of(), Instant.now().plusSeconds(3600));
        server.respond("/crl", 200, "application/pkix-crl", crl);

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/crl"));

        assertThat(status.state()).isEqualTo(RevocationState.GOOD);
    }

    @Test
    void aRevokedSerialIsReportedAsRevoked() throws Exception {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(null, server.baseUrl() + "/crl");
        byte[] crl = TestRevocationResponder.crl(
                identity.issuerCertificate(), identity.issuerPrivateKey(),
                List.of(identity.signerCertificate().getSerialNumber()), Instant.now().plusSeconds(3600));
        server.respond("/crl", 200, "application/pkix-crl", crl);

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/crl"));

        assertThat(status.state()).isEqualTo(RevocationState.REVOKED);
        assertThat(status.detail()).contains("revoked at");
    }

    @Test
    void aStaleCrlPastNextUpdateIsReportedAsUnknown() throws Exception {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(null, server.baseUrl() + "/crl");
        byte[] crl = TestRevocationResponder.crl(
                identity.issuerCertificate(), identity.issuerPrivateKey(), List.of(),
                Instant.now().minusSeconds(3600)); // nextUpdate already in the past
        server.respond("/crl", 200, "application/pkix-crl", crl);

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/crl"));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("stale");
    }

    @Test
    void anHttp500IsReportedAsUnknown() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(null, server.baseUrl() + "/crl");
        server.respond("/crl", 500, "text/plain", new byte[0]);

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/crl"));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("HTTP 500");
    }

    @Test
    void noCrlUrlIsReportedAsUnknown() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);

        RevocationStatus status =
                client(Duration.ofSeconds(2)).check(identity.signerCertificate(), identity.issuerCertificate(), List.of());

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("no CRL URL");
    }
}
