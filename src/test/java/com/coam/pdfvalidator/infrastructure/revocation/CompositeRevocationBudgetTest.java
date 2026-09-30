package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.fixtures.TestHttpServer;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.fixtures.TestRevocationResponder;
import com.coam.pdfvalidator.infrastructure.bouncycastle.X509CertificateInfoMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T21: the whole revocation check of one signature runs under ONE shared
 * deadline, every non-anchor certificate of the path is checked, and a slow
 * DNS server cannot stretch the request past its budget. The clock is fake,
 * so budget exhaustion is deterministic and no test sleeps for seconds.
 */
class CompositeRevocationBudgetTest {

    private static final long SECOND = 1_000_000_000L;

    private TestHttpServer server;
    private final AtomicLong fakeNanos = new AtomicLong(1_000L * SECOND);

    @BeforeEach
    void startServer() throws IOException {
        server = TestHttpServer.start();
    }

    @AfterEach
    void stopServer() {
        server.close();
    }

    private void advance(Duration duration) {
        fakeNanos.addAndGet(duration.toNanos());
    }

    private CompositeRevocationChecker checker(Duration timeout, Duration totalTimeout) {
        return checker(timeout, totalTimeout, HostResolver.systemDefault());
    }

    private CompositeRevocationChecker checker(Duration timeout, Duration totalTimeout, HostResolver resolver) {
        RevocationLimits limits = new RevocationLimits(timeout, totalTimeout, 10L * 1024 * 1024, 3, 8192, 100, 65536);
        return new CompositeRevocationChecker(limits, true, resolver, fakeNanos::get);
    }

    private static CertificateInfo toDomain(X509Certificate certificate) {
        return X509CertificateInfoMapper.toDomain(certificate);
    }

    private static CertificateInfo withUrls(CertificateInfo base, List<String> ocspUrls, List<String> crlUrls) {
        return new CertificateInfo(base.subject(), base.commonName(), base.issuer(), base.serialNumberHex(),
                base.notBefore(), base.notAfter(), base.signatureAlgorithm(), ocspUrls, crlUrls, base.encoded());
    }

    private AtomicInteger countingFailure(String path) {
        AtomicInteger hits = new AtomicInteger();
        server.respondDynamically(path, "application/octet-stream", body -> {
            hits.incrementAndGet();
            throw new IllegalStateException("always fail");
        });
        return hits;
    }

    private void ocspResponder(
            String path, X509Certificate issuer, PrivateKey issuerKey, TestRevocationResponder.OcspOutcome outcome,
            AtomicInteger hits, Duration clockAdvance) {
        server.respondDynamically(path, "application/ocsp-response", request -> {
            hits.incrementAndGet();
            advance(clockAdvance);
            return TestRevocationResponder.ocspResponse(request, issuer, issuerKey, outcome);
        });
    }

    // ---- shared total budget ----

    @Test
    void onceTheTotalBudgetIsSpentNoFurtherOcspOrCrlUrlIsContacted() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);
        server.respondDynamically("/o1", "application/octet-stream", body -> {
            advance(Duration.ofSeconds(7)); // this attempt alone consumes the 6 s budget
            throw new IllegalStateException("fail");
        });
        AtomicInteger later = countingFailure("/o2");
        AtomicInteger crl = countingFailure("/c1");
        CertificateInfo signer = withUrls(toDomain(identity.signerCertificate()),
                List.of(server.baseUrl() + "/o1", server.baseUrl() + "/o2"), List.of(server.baseUrl() + "/c1"));

        RevocationStatus status = checker(Duration.ofSeconds(2), Duration.ofSeconds(6))
                .check(signer, toDomain(identity.issuerCertificate()));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("budget exhausted");
        assertThat(later.get()).isZero();
        assertThat(crl.get()).isZero();
    }

    @Test
    void theBudgetIsSharedByAllCertificatesOfThePath() {
        TestPki.ThreeTierRevocationIdentity pki = TestPki.issueThreeTierRevocationIdentity(
                server.baseUrl() + "/ca", server.baseUrl() + "/leaf");
        AtomicInteger leafHits = new AtomicInteger();
        AtomicInteger caHits = new AtomicInteger();
        ocspResponder("/leaf", pki.intermediateCertificate(), pki.intermediatePrivateKey(),
                TestRevocationResponder.OcspOutcome.GOOD, leafHits, Duration.ofSeconds(7));
        ocspResponder("/ca", pki.rootCertificate(), pki.rootPrivateKey(),
                TestRevocationResponder.OcspOutcome.GOOD, caHits, Duration.ZERO);

        RevocationStatus status = checker(Duration.ofSeconds(2), Duration.ofSeconds(6)).checkPath(path(pki));

        assertThat(leafHits.get()).isEqualTo(1);
        assertThat(caHits.get()).isZero();
        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("CA certificate").contains("budget exhausted");
    }

    @Test
    void aPerRequestTimeoutLongerThanTheRemainingBudgetIsCappedByTheBudget() throws Exception {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);
        server.respondAfterDelay("/slow", Duration.ofSeconds(2), 200, "application/ocsp-response", new byte[] {1});
        CertificateInfo signer = withUrls(toDomain(identity.signerCertificate()),
                List.of(server.baseUrl() + "/slow"), List.of());
        // Real time: the socket deadline is real even though the budget clock is fake.
        CompositeRevocationChecker checker = new CompositeRevocationChecker(
                new RevocationLimits(Duration.ofSeconds(5), Duration.ofMillis(300), 1024, 3, 8192, 100, 65536),
                true, HostResolver.systemDefault(), System::nanoTime);

        long start = System.nanoTime();
        RevocationStatus status = checker.check(signer, toDomain(identity.issuerCertificate()));
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("timed out");
        assertThat(elapsedMillis).isLessThan(1500);
    }

    // ---- every non-anchor certificate of the path ----

    private static List<CertificateInfo> path(TestPki.ThreeTierRevocationIdentity pki) {
        return List.of(toDomain(pki.endEntityCertificate()), toDomain(pki.intermediateCertificate()),
                toDomain(pki.rootCertificate()));
    }

    @Test
    void aRevokedIntermediateRevokesThePathEvenWhenTheLeafIsGood() {
        TestPki.ThreeTierRevocationIdentity pki = TestPki.issueThreeTierRevocationIdentity(
                server.baseUrl() + "/ca", server.baseUrl() + "/leaf");
        ocspResponder("/leaf", pki.intermediateCertificate(), pki.intermediatePrivateKey(),
                TestRevocationResponder.OcspOutcome.GOOD, new AtomicInteger(), Duration.ZERO);
        ocspResponder("/ca", pki.rootCertificate(), pki.rootPrivateKey(),
                TestRevocationResponder.OcspOutcome.REVOKED, new AtomicInteger(), Duration.ZERO);

        RevocationStatus status = checker(Duration.ofSeconds(2), Duration.ofSeconds(6)).checkPath(path(pki));

        assertThat(status.state()).isEqualTo(RevocationState.REVOKED);
        assertThat(status.source()).endsWith("/ca");
        assertThat(status.detail()).startsWith("CA certificate '").contains("revoked at");
    }

    @Test
    void aRevokedLeafStopsTheCheckWithoutContactingTheCaAndKeepsItsPlainDetail() {
        TestPki.ThreeTierRevocationIdentity pki = TestPki.issueThreeTierRevocationIdentity(
                server.baseUrl() + "/ca", server.baseUrl() + "/leaf");
        AtomicInteger caHits = new AtomicInteger();
        ocspResponder("/leaf", pki.intermediateCertificate(), pki.intermediatePrivateKey(),
                TestRevocationResponder.OcspOutcome.REVOKED, new AtomicInteger(), Duration.ZERO);
        ocspResponder("/ca", pki.rootCertificate(), pki.rootPrivateKey(),
                TestRevocationResponder.OcspOutcome.GOOD, caHits, Duration.ZERO);

        RevocationStatus status = checker(Duration.ofSeconds(2), Duration.ofSeconds(6)).checkPath(path(pki));

        assertThat(status.state()).isEqualTo(RevocationState.REVOKED);
        assertThat(status.detail()).startsWith("revoked at");
        assertThat(caHits.get()).isZero();
    }

    @Test
    void aPathWhereEveryNonAnchorCertificateIsGoodIsGoodAndTheAnchorIsNeverContacted() {
        TestPki.ThreeTierRevocationIdentity pki = TestPki.issueThreeTierRevocationIdentity(
                server.baseUrl() + "/ca", server.baseUrl() + "/leaf");
        AtomicInteger caHits = new AtomicInteger();
        ocspResponder("/leaf", pki.intermediateCertificate(), pki.intermediatePrivateKey(),
                TestRevocationResponder.OcspOutcome.GOOD, new AtomicInteger(), Duration.ZERO);
        ocspResponder("/ca", pki.rootCertificate(), pki.rootPrivateKey(),
                TestRevocationResponder.OcspOutcome.GOOD, caHits, Duration.ZERO);

        RevocationStatus status = checker(Duration.ofSeconds(2), Duration.ofSeconds(6)).checkPath(path(pki));

        assertThat(status.state()).isEqualTo(RevocationState.GOOD);
        assertThat(caHits.get()).isEqualTo(1); // the intermediate's own OCSP URL, answered by the root
    }

    @Test
    void anIntermediateWithoutAnyRevocationUrlMakesThePathUnknown() {
        TestPki.ThreeTierRevocationIdentity pki = TestPki.issueThreeTierRevocationIdentity(
                null, server.baseUrl() + "/leaf");
        ocspResponder("/leaf", pki.intermediateCertificate(), pki.intermediatePrivateKey(),
                TestRevocationResponder.OcspOutcome.GOOD, new AtomicInteger(), Duration.ZERO);

        RevocationStatus status = checker(Duration.ofSeconds(2), Duration.ofSeconds(6)).checkPath(path(pki));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(status.detail()).contains("CA certificate").contains("no OCSP/CRL URL");
    }

    // ---- DNS under the deadline ----

    @Test
    void aSlowDnsServerCannotStretchTheCheckPastItsTimeout() throws Exception {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);
        CountDownLatch release = new CountDownLatch(1);
        HostResolver hanging = host -> {
            boolean released = false;
            while (!released) {
                try {
                    release.await();
                    released = true;
                } catch (InterruptedException e) {
                    // ignore, like a native resolver call would
                }
            }
            return new InetAddress[] {InetAddress.getLoopbackAddress()};
        };
        CertificateInfo signer = withUrls(toDomain(identity.signerCertificate()),
                List.of("http://slow-dns.example.org/ocsp"), List.of("http://slow-dns.example.org/crl"));
        CompositeRevocationChecker checker = new CompositeRevocationChecker(
                new RevocationLimits(Duration.ofMillis(200), Duration.ofSeconds(2), 1024, 3, 8192, 100, 65536),
                true, hanging, System::nanoTime);

        try {
            long start = System.nanoTime();
            RevocationStatus status = checker.check(signer, toDomain(identity.issuerCertificate()));
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

            assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
            assertThat(status.detail()).contains("within the time limit");
            assertThat(elapsedMillis).isLessThan(1500);
        } finally {
            release.countDown();
        }
    }
}
