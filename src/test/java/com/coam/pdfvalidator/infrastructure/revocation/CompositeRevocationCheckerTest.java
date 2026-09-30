package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.fixtures.RawSocketTestServer;
import com.coam.pdfvalidator.fixtures.TestHttpServer;
import com.coam.pdfvalidator.fixtures.TestPki;
import com.coam.pdfvalidator.fixtures.TestRevocationResponder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

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
     * A malformed OCSP response (negative {@code Content-Length}, which
     * would throw an unchecked {@code NegativeArraySizeException} without
     * {@link PinnedHttpClient}'s validation) must still surface as {@code
     * UNKNOWN}, never as an exception out of this adapter
     * (R3-unchecked-parse-escapes, defense in depth end to end).
     */
    @Test
    void aMalformedOcspResponseIsUnknownNotAnException() throws Exception {
        try (RawSocketTestServer malformed = RawSocketTestServer.start()) {
            malformed.respondWithChunks(List.of(
                    "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n".getBytes(StandardCharsets.US_ASCII)), 0);
            TestPki.RevocationTestIdentity identity =
                    TestPki.issueRevocationTestIdentity(malformed.baseUrl() + "/ocsp", null);

            RevocationStatus status =
                    checker().check(toDomain(identity.signerCertificate()), toDomain(identity.issuerCertificate()));

            assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        }
    }

    /**
     * T10b: the safe wrappers around {@code OcspClient}/{@code CrlClient}
     * (defense in depth against those adapters' own "never throws" contract)
     * previously swallowed an unexpected {@link RuntimeException} silently.
     * Exercises the wrapper's own catch-and-log behavior directly (a package-
     * private seam, same convention as {@code PreflightPdfaValidator#mapErrors}):
     * the exception's class name is logged, never its (potentially sensitive)
     * message, and the reported result stays {@code UNKNOWN}.
     */
    @Test
    void aRuntimeExceptionFromAWrappedCheckIsLoggedByClassNameOnlyAndReportedAsUnknown() {
        Logger julLogger = Logger.getLogger(CompositeRevocationChecker.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        julLogger.addHandler(handler);
        julLogger.setLevel(Level.ALL);
        try {
            RevocationStatus status = checker().safely(
                    "OCSP", () -> {
                        throw new IllegalStateException("sensitive-detail-must-never-be-logged");
                    });

            assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
            assertThat(status.detail()).isEqualTo("OCSP check failed (unexpected error)");
            assertThat(records).isNotEmpty();
            String logged = records.stream().map(LogRecord::getMessage).reduce("", String::concat);
            assertThat(logged).contains("IllegalStateException");
            assertThat(logged).doesNotContain("sensitive-detail-must-never-be-logged");
        } finally {
            julLogger.removeHandler(handler);
        }
    }

    /**
     * Reuses this project's own {@code X509CertificateInfoMapper} (the same
     * mapper {@code BcSignatureVerifier} uses in production) instead of
     * duplicating AIA/CDP-extraction logic in a test -- it is public
     * exactly for this kind of infra-internal reuse, see its own Javadoc.
     */
    // ---- T21b: URL deduplication and per-method cap ----

    private static CertificateInfo withUrls(CertificateInfo base, List<String> ocspUrls, List<String> crlUrls) {
        return new CertificateInfo(base.subject(), base.commonName(), base.issuer(), base.serialNumberHex(),
                base.notBefore(), base.notAfter(), base.signatureAlgorithm(), ocspUrls, crlUrls, base.encoded());
    }

    /** Registers {@code count} paths under {@code prefix} that count their hits and answer HTTP 500. */
    private java.util.concurrent.atomic.AtomicInteger countHits(String prefix, int count) {
        java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
        for (int i = 1; i <= count; i++) {
            server.respondDynamically(prefix + i, "application/octet-stream", body -> {
                hits.incrementAndGet();
                throw new IllegalStateException("always fail");
            });
        }
        return hits;
    }

    private List<String> urls(String prefix, int count) {
        List<String> urls = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            urls.add(server.baseUrl() + prefix + i);
        }
        return urls;
    }

    @Test
    void atMostThreeOcspUrlsAreContactedPerCertificate() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);
        java.util.concurrent.atomic.AtomicInteger hits = countHits("/o", 6);
        CertificateInfo signer = withUrls(toDomain(identity.signerCertificate()), urls("/o", 6), List.of());

        RevocationStatus status = checker().check(signer, toDomain(identity.issuerCertificate()));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(hits.get()).isEqualTo(3);
    }

    @Test
    void atMostThreeCrlUrlsAreContactedPerCertificate() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);
        java.util.concurrent.atomic.AtomicInteger hits = countHits("/c", 6);
        CertificateInfo signer = withUrls(toDomain(identity.signerCertificate()), List.of(), urls("/c", 6));

        RevocationStatus status = checker().check(signer, toDomain(identity.issuerCertificate()));

        assertThat(status.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(hits.get()).isEqualTo(3);
    }

    @Test
    void duplicateUrlsAreContactedOnlyOnce() {
        TestPki.RevocationTestIdentity identity = TestPki.issueRevocationTestIdentity(null, null);
        java.util.concurrent.atomic.AtomicInteger hits = countHits("/o", 1);
        String url = server.baseUrl() + "/o1";
        CertificateInfo signer = withUrls(toDomain(identity.signerCertificate()), List.of(url, url, url), List.of());

        checker().check(signer, toDomain(identity.issuerCertificate()));

        assertThat(hits.get()).isEqualTo(1);
    }

    private static CertificateInfo toDomain(X509Certificate certificate) {
        return com.coam.pdfvalidator.infrastructure.bouncycastle.X509CertificateInfoMapper.toDomain(certificate);
    }
}
