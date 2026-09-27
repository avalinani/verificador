package com.coam.pdfvalidator.api;

import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T09b regression: a real upload exceeding the configured multipart size
 * limit must produce a {@code 413} with the same {@code ProblemDetail} body
 * every other error uses -- previously observed (manual run) as a bare
 * {@code 413} with an <b>empty</b> body, since {@code
 * MaxUploadSizeExceededException} is thrown before Spring resolves a
 * handler for the request (see {@code MaxUploadSizeExceptionHandler}'s
 * Javadoc), so {@code PdfAnalysisExceptionHandler}'s controller-scoped
 * advice could never see it.
 *
 * <p>Uses a real embedded servlet container ({@code webEnvironment =
 * RANDOM_PORT} + a plain JDK {@link HttpClient}), not {@code MockMvc}: the
 * multipart size limit is enforced by the actual servlet container's
 * request parsing, which {@code MockMvc} (a plain in-memory {@code
 * MockMultipartHttpServletRequest}, never a real HTTP request) does not
 * reproduce -- confirmed empirically: the same oversized upload through
 * {@code MockMvc} returned {@code 400} (its usual {@code not-a-pdf}
 * handling), never {@code 413} at all. Runs in its own Spring context (a
 * separate test class, not added to {@link PdfAnalysisEndToEndTest}) with
 * the multipart limit lowered to 1 KB via {@link TestPropertySource}, so a
 * small in-memory payload is enough to exceed it -- no need to actually
 * build a >20 MB request.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "spring.servlet.multipart.max-file-size=1KB",
        "spring.servlet.multipart.max-request-size=1KB"
})
class MaxUploadSizeExceptionHandlerIntegrationTest {

    @LocalServerPort
    private int port;

    @Test
    void anUploadExceedingTheConfiguredLimitReturns413WithAProblemDetailBody() throws Exception {
        String boundary = "----pdfvalidatorTestBoundary";
        byte[] tooLarge = new byte[8192];

        StringBuilder head = new StringBuilder();
        head.append("--").append(boundary).append("\r\n");
        head.append("Content-Disposition: form-data; name=\"file\"; filename=\"big.pdf\"\r\n");
        head.append("Content-Type: application/pdf\r\n\r\n");
        String tail = "\r\n--" + boundary + "--\r\n";

        byte[] headBytes = head.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] tailBytes = tail.getBytes(StandardCharsets.US_ASCII);
        byte[] fullBody = new byte[headBytes.length + tooLarge.length + tailBytes.length];
        System.arraycopy(headBytes, 0, fullBody, 0, headBytes.length);
        System.arraycopy(tooLarge, 0, fullBody, headBytes.length, tooLarge.length);
        System.arraycopy(tailBytes, 0, fullBody, headBytes.length + tooLarge.length, tailBytes.length);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/pdf/analyze"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(fullBody))
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(413);
        assertThat(response.body())
                .as("the body must not be empty (T09b regression)")
                .isNotBlank()
                .contains("urn:pdfvalidator:error:file-too-large");
        List<String> contentType = response.headers().allValues("Content-Type");
        assertThat(contentType).anyMatch(value -> value.contains("application/problem+json"));
    }
}
