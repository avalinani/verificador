package com.coam.pdfvalidator.api.concurrency;

import com.coam.pdfvalidator.application.AnalysisOptions;
import com.coam.pdfvalidator.application.AnalyzePdfUseCase;
import com.coam.pdfvalidator.domain.model.DocumentHashes;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.domain.model.Permission;
import com.coam.pdfvalidator.domain.model.SecurityInfo;

import com.coam.pdfvalidator.api.PdfAnalysisController;

import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * T12c: with {@code max-concurrent=1}, a second concurrent upload is answered
 * {@code 503} + {@code Retry-After} while the first analysis is held (a
 * latch-controlled fake use case), and the permit is released afterwards.
 * Runs against a real embedded server: the bulkhead is a servlet filter that
 * must act before multipart parsing, which {@code MockMvc} cannot show.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "pdfvalidator.analysis.max-concurrent=1",
        "pdfvalidator.analysis.acquire-timeout=200ms"
})
class AnalysisBulkheadIntegrationTest {

    private static final String BOUNDARY = "----bulkheadBoundary";
    private static final String ANALYZE = PdfAnalysisController.ANALYZE_PATH;

    @LocalServerPort
    private int port;

    @MockitoBean
    private AnalyzePdfUseCase analyzePdfUseCase;

    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void aSecondConcurrentRequestGets503WhileTheFirstIsHeldAndPermitsAreReleasedAfterwards() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenAnswer(invocation -> {
                    entered.countDown();
                    if (!release.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("test latch never released");
                    }
                    return report();
                });

        CompletableFuture<HttpResponse<String>> first =
                client.sendAsync(request(), HttpResponse.BodyHandlers.ofString());
        assertThat(entered.await(10, TimeUnit.SECONDS)).as("first analysis started").isTrue();

        HttpResponse<String> second = client.send(request(), HttpResponse.BodyHandlers.ofString());

        assertThat(second.statusCode()).isEqualTo(503);
        assertThat(second.headers().firstValue("Retry-After")).contains("1");
        assertThat(second.headers().allValues("Content-Type"))
                .anyMatch(value -> value.contains("application/problem+json"));
        assertThat(second.body()).contains("urn:pdfvalidator:error:busy");

        release.countDown();
        assertThat(first.get(10, TimeUnit.SECONDS).statusCode()).isEqualTo(200);

        HttpResponse<String> third = client.send(request(), HttpResponse.BodyHandlers.ofString());
        assertThat(third.statusCode()).as("permit released after the first request finished").isEqualTo(200);
    }

    @Test
    void thePermitIsReleasedWhenTheAnalysisFails() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenThrow(new IllegalStateException("boom"));

        for (int i = 0; i < 3; i++) {
            assertThat(client.send(request(), HttpResponse.BodyHandlers.ofString()).statusCode())
                    .as("request %d must reach the use case, never 503", i).isEqualTo(500);
        }
    }

    /** Spellings that could reach the controller (or be routed elsewhere) and must not bypass the limit. */
    private static final List<String> VARIANTS = List.of(
            ANALYZE,
            ANALYZE + "/",
            ANALYZE + ";jsessionid=x",
            "/" + ANALYZE,
            "/api/v1/pdf/%61nalyze",
            "/API/v1/pdf/analyze",
            "/api/v1/pdf/./analyze",
            "/api/v1/pdf/x/../analyze");

    /**
     * Every spelling of the upload path that the servlet container or Spring
     * MVC might route to the controller must be limited too. With the only
     * permit held, each variant must be answered 503 by the bulkhead: never
     * reach the controller, never 200.
     */
    @Test
    void everyUriVariantOfTheUploadEndpointIsLimitedWhileThePermitIsHeld() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenAnswer(invocation -> {
                    entered.countDown();
                    if (!release.await(20, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("test latch never released");
                    }
                    return report();
                });
        CompletableFuture<HttpResponse<String>> first =
                client.sendAsync(request(), HttpResponse.BodyHandlers.ofString());
        assertThat(entered.await(10, TimeUnit.SECONDS)).as("first analysis started").isTrue();

        Map<String, Integer> statuses = new LinkedHashMap<>();
        for (String variant : VARIANTS) {
            statuses.put(variant, client.send(request(variant), HttpResponse.BodyHandlers.ofString()).statusCode());
        }
        release.countDown();
        first.get(10, TimeUnit.SECONDS);

        assertThat(statuses).as("status per URI variant while the only permit is held")
                .allSatisfy((variant, status) -> assertThat(status).as(variant).isEqualTo(503));
    }

    /**
     * Without contention, shows where each variant ends up: served by the
     * controller (200) or rejected before it (404). The test above
     * proves both classes are limited.
     */
    @Test
    void whenIdleEachUriVariantIsEitherServedByTheControllerOrRejectedBySpring() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenReturn(report());

        Map<String, Integer> statuses = new LinkedHashMap<>();
        for (String variant : VARIANTS) {
            statuses.put(variant, client.send(request(variant), HttpResponse.BodyHandlers.ofString()).statusCode());
        }

        assertThat(statuses).containsEntry(ANALYZE, 200)
                .containsEntry(ANALYZE + "/", 404)
                .containsEntry(ANALYZE + ";jsessionid=x", 200)
                .containsEntry("/" + ANALYZE, 404)
                .containsEntry("/api/v1/pdf/%61nalyze", 200)
                .containsEntry("/API/v1/pdf/analyze", 404)
                .containsEntry("/api/v1/pdf/./analyze", 404)
                .containsEntry("/api/v1/pdf/x/../analyze", 404);
    }

    /**
     * The rejected upload's body is never read, so the 503 must tell the
     * container to drop the connection instead of draining it. A raw socket
     * announces a 20 MB body, sends a fraction of it and must still get the
     * 503 and an end of stream promptly.
     */
    @Test
    void aRejectedUploadIsAnsweredWithConnectionCloseWithoutWaitingForTheBody() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenAnswer(invocation -> {
                    entered.countDown();
                    if (!release.await(20, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("test latch never released");
                    }
                    return report();
                });
        CompletableFuture<HttpResponse<String>> first =
                client.sendAsync(request(), HttpResponse.BodyHandlers.ofString());
        assertThat(entered.await(10, TimeUnit.SECONDS)).as("first analysis started").isTrue();

        long announced = 20L * 1024 * 1024;
        try (Socket socket = new Socket("localhost", port)) {
            socket.setSoTimeout(8_000);
            OutputStream out = socket.getOutputStream();
            out.write(("POST " + ANALYZE + " HTTP/1.1\r\nHost: localhost\r\n"
                    + "Content-Type: multipart/form-data; boundary=" + BOUNDARY + "\r\n"
                    + "Content-Length: " + announced + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            // A real client keeps streaming its 20 MB body while it waits for the answer.
            Thread uploader = Thread.startVirtualThread(() -> {
                try {
                    byte[] chunk = new byte[64 * 1024];
                    for (long sent = 0; sent < announced; sent += chunk.length) {
                        out.write(chunk);
                        out.flush();
                    }
                } catch (java.io.IOException closedByServer) {
                    // expected: the server drops the connection instead of draining the body
                }
            });

            long start = System.nanoTime();
            InputStream in = socket.getInputStream();
            String response = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

            uploader.interrupt();
            assertThat(response).startsWith("HTTP/1.1 503");
            assertThat(response.toLowerCase(Locale.ROOT)).contains("connection: close");
            assertThat(elapsedMs).as("connection closed promptly, body not drained").isLessThan(3_000);
        } finally {
            release.countDown();
            first.get(10, TimeUnit.SECONDS);
        }
    }

    /**
     * A small unread body would let Tomcat keep the connection alive and drain
     * it; the 503 must ask for the connection to be closed explicitly, not
     * only rely on Tomcat's swallow limit for large bodies.
     */
    @Test
    void aRejectedSmallUploadAlsoAsksForTheConnectionToBeClosed() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenAnswer(invocation -> {
                    entered.countDown();
                    if (!release.await(20, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("test latch never released");
                    }
                    return report();
                });
        CompletableFuture<HttpResponse<String>> first =
                client.sendAsync(request(), HttpResponse.BodyHandlers.ofString());
        assertThat(entered.await(10, TimeUnit.SECONDS)).as("first analysis started").isTrue();

        try (Socket socket = new Socket("localhost", port)) {
            socket.setSoTimeout(5_000);
            byte[] body = new byte[1024];
            OutputStream out = socket.getOutputStream();
            out.write(("POST " + ANALYZE + " HTTP/1.1\r\nHost: localhost\r\n"
                    + "Content-Type: multipart/form-data; boundary=" + BOUNDARY + "\r\n"
                    + "Content-Length: " + body.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(body);
            out.flush();

            String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);

            assertThat(response).startsWith("HTTP/1.1 503");
            assertThat(response.toLowerCase(Locale.ROOT)).contains("connection: close");
        } finally {
            release.countDown();
            first.get(10, TimeUnit.SECONDS);
        }
    }

    private HttpRequest request() {
        return request(ANALYZE);
    }

    private HttpRequest request(String path) {
        byte[] head = ("--" + BOUNDARY + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.pdf\"\r\n"
                + "Content-Type: application/pdf\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
        byte[] pdf = "%PDF-1.7\n...".getBytes(StandardCharsets.US_ASCII);
        byte[] tail = ("\r\n--" + BOUNDARY + "--\r\n").getBytes(StandardCharsets.US_ASCII);
        byte[] body = new byte[head.length + pdf.length + tail.length];
        System.arraycopy(head, 0, body, 0, head.length);
        System.arraycopy(pdf, 0, body, head.length, pdf.length);
        System.arraycopy(tail, 0, body, head.length + pdf.length, tail.length);
        return HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
    }

    private static PdfAnalysisReport report() {
        DocumentStructure structure = new DocumentStructure("1.7", null, 0, List.of(), 1);
        SecurityInfo security = new SecurityInfo(false, EnumSet.noneOf(Permission.class));
        PdfaReport pdfa = new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of());
        return new PdfAnalysisReport("a.pdf", 12, new DocumentHashes("a".repeat(64), "b".repeat(128)),
                structure, security, pdfa, List.of(), Instant.parse("2026-09-29T10:00:00Z"), List.of());
    }
}
