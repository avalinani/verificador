package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.fixtures.TestHttpServer;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.fixtures.TestRevocationResponder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.security.Provider;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link OcspClient} against a real, in-process HTTP server ({@link
 * TestHttpServer}) serving real, cryptographically signed OCSP responses
 * ({@link TestRevocationResponder}) -- chosen over WireMock for this task
 * to avoid any risk of a Jetty/Guava classpath clash with Spring Boot
 * 4.1.1's own (newer) Jetty bring-up; a plain {@code
 * com.sun.net.httpserver.HttpServer} needs no extra dependency and is
 * enough to drive every OCSP request/response case this task specifies.
 */
class OcspClientTest {

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    private TestHttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        server = TestHttpServer.start();
    }

    @AfterEach
    void stopServer() {
        server.close();
    }

    private OcspClient client(Duration timeout) {
        return client(timeout, HostResolver.systemDefault());
    }

    private OcspClient client(Duration timeout, HostResolver resolver) {
        // allowPrivateAddresses=true: this test's server is bound to 127.0.0.1.
        return new OcspClient(timeout, 10 * 1024 * 1024, true, resolver, BC_PROVIDER);
    }

    @Test
    void aGoodResponseIsReportedAsGood() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(server.baseUrl() + "/ocsp", null);
        respondWithOcspOutcome(identity, TestRevocationResponder.OcspOutcome.GOOD);

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/ocsp"));

        assertThat(status.state()).isEqualTo(RevocationState.GOOD);
        assertThat(status.source()).isEqualTo(server.baseUrl() + "/ocsp");
    }

    @Test
    void aRevokedResponseIsReportedAsRevokedWithADetail() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(server.baseUrl() + "/ocsp", null);
        respondWithOcspOutcome(identity, TestRevocationResponder.OcspOutcome.REVOKED);

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/ocsp"));

        assertThat(status.state()).isEqualTo(RevocationState.REVOKED);
        assertThat(status.detail()).contains("revoked at");
    }

    @Test
    void anUnknownStatusIsReportedAsUnknown() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(server.baseUrl() + "/ocsp", null);
        respondWithOcspOutcome(identity, TestRevocationResponder.OcspOutcome.UNKNOWN_STATUS);

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/ocsp"));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("does not know this certificate");
    }

    @Test
    void aBadSignatureIsReportedAsUnknown() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(server.baseUrl() + "/ocsp", null);
        server.respondDynamically("/ocsp", "application/ocsp-response",
                requestBytes -> TestRevocationResponder.ocspResponseWithBadSignature(
                        requestBytes, identity.issuerCertificate()));

        RevocationStatus status = client(Duration.ofSeconds(2)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/ocsp"));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("signature is invalid");
    }

    @Test
    void aTimeoutIsReportedAsUnknown() {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity(server.baseUrl() + "/ocsp", null);
        server.respondAfterDelay("/ocsp", Duration.ofSeconds(3), 200, "application/ocsp-response", new byte[0]);

        RevocationStatus status = client(Duration.ofMillis(300)).check(
                identity.signerCertificate(), identity.issuerCertificate(), List.of(server.baseUrl() + "/ocsp"));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("timed out");
    }

    @Test
    void noOcspUrlIsReportedAsUnknown() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);

        RevocationStatus status =
                client(Duration.ofSeconds(2)).check(identity.signerCertificate(), identity.issuerCertificate(), List.of());

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("no OCSP URL");
    }

    /**
     * The DNS-rebinding proof at the OCSP-client level (mirrors {@code
     * RevocationUrlGuardTest}'s guard-level proof, but exercises the real
     * end-to-end path including {@link PinnedHttpClient}): a resolver that
     * returns the test server's real address on its single call must be
     * the address {@link OcspClient} actually connects to -- if it instead
     * re-resolved and got a different (unserved) address, this request
     * would fail to connect rather than getting the real GOOD response
     * back.
     */
    @Test
    void connectsToThePinnedAddressFromASingleResolution() throws Exception {
        TestPki.RevocationTestIdentity identity =
                TestPki.issueRevocationTestIdentity("http://revocation.example.test/ocsp", null);
        respondWithOcspOutcome(identity, TestRevocationResponder.OcspOutcome.GOOD);

        InetAddress realServerAddress = InetAddress.getByName("127.0.0.1");
        InetAddress unservedAddress = InetAddress.getByName("127.0.0.2");
        AtomicReference<Integer> resolveCalls = new AtomicReference<>(0);
        HostResolver rebindingResolver = host -> {
            resolveCalls.set(resolveCalls.get() + 1);
            // Only the FIRST call may ever be observed: the client must
            // resolve exactly once and use that single result, never call
            // the resolver again to "double-check" or reconnect.
            return resolveCalls.get() == 1 ? new InetAddress[] {realServerAddress} : new InetAddress[] {unservedAddress};
        };

        RevocationStatus status = client(Duration.ofSeconds(2), rebindingResolver).check(
                identity.signerCertificate(), identity.issuerCertificate(),
                List.of("http://revocation.example.test:" + server.port() + "/ocsp"));

        assertThat(status.state()).isEqualTo(RevocationState.GOOD);
        assertThat(resolveCalls.get()).isEqualTo(1);
    }

    private void respondWithOcspOutcome(TestPki.RevocationTestIdentity identity, TestRevocationResponder.OcspOutcome outcome) {
        server.respondDynamically("/ocsp", "application/ocsp-response",
                requestBytes -> TestRevocationResponder.ocspResponse(
                        requestBytes, identity.issuerCertificate(), identity.issuerPrivateKey(), outcome));
    }
}
