package com.coam.pdfvalidator.api;

import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The deployed service sits behind Caddy, which terminates HTTPS and forwards
 * to the app over plain HTTP on loopback with {@code X-Forwarded-Proto} and
 * {@code X-Forwarded-Host}. springdoc builds the OpenAPI {@code servers} URL
 * from the request, so unless the app honours those headers the public spec
 * advertises {@code http://…} and Swagger UI's "Try it out", served over
 * HTTPS, calls a different origin and fails (reported as a CORS error).
 * Real HTTP is needed here: the forwarded headers are applied by Tomcat
 * ({@code server.forward-headers-strategy=native}), which MockMvc bypasses.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ForwardedHeadersIntegrationTest {

    @LocalServerPort
    private int port;

    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void theOpenApiServerUrlFollowsTheProxySchemeAndHost() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v3/api-docs"))
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "validator.example.org")
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"url\":\"https://validator.example.org\"");
    }

    @Test
    void withoutProxyHeadersTheServerUrlIsTheDirectOne() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v3/api-docs"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"url\":\"http://localhost:" + port + "\"");
    }
}
