package com.coam.pdfvalidator.api.concurrency;

import com.coam.pdfvalidator.api.PdfAnalysisController;
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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * T26b: the bulkhead permit is taken before the multipart body is read, so a client that stops sending its body
 * must not keep the permit for longer than the Tomcat read timeout ({@code server.tomcat.connection-timeout};
 * 1 s here, {@code application.yml} sets the real value). A raw socket announces a body, sends a few bytes and
 * goes silent without closing the connection. A client that keeps trickling bytes is not stopped by this
 * timeout; the reverse proxy's {@code read_body} deadline (deploy/Caddyfile) covers that case.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "pdfvalidator.analysis.max-concurrent=1",
        "pdfvalidator.analysis.acquire-timeout=100ms",
        "server.tomcat.connection-timeout=1s"
})
class SlowUploadIntegrationTest {

    private static final String BOUNDARY = "----slowUploadBoundary";
    private static final String CRLF = "\r\n";
    private static final String ANALYZE = PdfAnalysisController.ANALYZE_PATH;

    @LocalServerPort
    private int port;

    @MockitoBean
    private AnalyzePdfUseCase analyzePdfUseCase;

    @Autowired
    private AnalysisBulkhead bulkhead;

    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void aClientThatStopsSendingItsBodyHoldsThePermitOnlyUntilTheReadTimeout() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenReturn(report());

        try (Socket stalled = new Socket("localhost", port)) {
            OutputStream out = stalled.getOutputStream();
            String head = "POST " + ANALYZE + " HTTP/1.1" + CRLF
                    + "Host: localhost" + CRLF
                    + "Content-Type: multipart/form-data; boundary=" + BOUNDARY + CRLF
                    + "Content-Length: 100000" + CRLF + CRLF
                    + "--" + BOUNDARY + CRLF;
            out.write(head.getBytes(StandardCharsets.US_ASCII));
            out.flush(); // ...and then nothing, with the connection left open

            assertThat(permitsAvailableWithin(5, 0)).as("the stalled upload takes the only permit").isTrue();
            assertThat(permitsAvailableWithin(15, 1)).as("the permit is released once the read times out").isTrue();
        }

        HttpResponse<String> next = client.send(request(), HttpResponse.BodyHandlers.ofString());
        assertThat(next.statusCode()).as("a well-formed upload is served afterwards").isEqualTo(200);
    }

    /** Polls the bulkhead until it has exactly {@code permits} free, for at most {@code seconds}. */
    private boolean permitsAvailableWithin(int seconds, int permits) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        while (System.nanoTime() < deadline) {
            if (bulkhead.availablePermits() == permits) {
                return true;
            }
            Thread.sleep(20);
        }
        return false;
    }

    private HttpRequest request() {
        String body = "--" + BOUNDARY + CRLF
                + "Content-Disposition: form-data; name=\"file\"; filename=\"a.pdf\"" + CRLF
                + "Content-Type: application/pdf" + CRLF + CRLF
                + "%PDF-1.7" + CRLF + "--" + BOUNDARY + "--" + CRLF;
        return HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + ANALYZE))
                .header("Content-Type", "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
    }

    private static PdfAnalysisReport report() {
        DocumentStructure structure = new DocumentStructure("1.7", null, 0, List.of(), 1);
        SecurityInfo security = new SecurityInfo(false, EnumSet.noneOf(Permission.class));
        PdfaReport pdfa = new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of());
        return new PdfAnalysisReport("a.pdf", 12, new DocumentHashes("a".repeat(64), "b".repeat(128)),
                structure, security, pdfa, List.of(), Instant.parse("2026-10-01T10:00:00Z"), List.of());
    }
}
