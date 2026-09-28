package com.coam.pdfvalidator.fixtures;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.Executors;

/**
 * A tiny, real, loopback-bound HTTP server used only by this project's
 * tests (OCSP/CRL revocation checking, T10) -- chosen over WireMock to keep
 * a single JDK-only dependency for both fetches, avoiding any risk of a
 * Jetty/Guava classpath clash with Spring Boot 4.1.1's own (newer) Jetty
 * bring-up. Never use this in production code.
 */
public final class TestHttpServer implements AutoCloseable {

    private final HttpServer server;

    private TestHttpServer(HttpServer server) {
        this.server = server;
    }

    public static TestHttpServer start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        return new TestHttpServer(server);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /** A URL using {@code 127.0.0.1} literally (never {@code localhost}), for predictable DNS-free tests. */
    public String baseUrl() {
        return "http://127.0.0.1:" + port();
    }

    public void respond(String path, int status, String contentType, byte[] body) {
        server.createContext(path, exchange -> {
            exchange.getResponseHeaders().add("Content-Type", contentType);
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                if (body.length > 0) {
                    os.write(body);
                }
            }
        });
    }

    /** Builds its response from the request body -- needed for OCSP, whose response must echo the request's certID/nonce. */
    @FunctionalInterface
    public interface DynamicHandler {
        byte[] handle(byte[] requestBody) throws Exception;
    }

    public void respondDynamically(String path, String contentType, DynamicHandler handler) {
        server.createContext(path, exchange -> {
            byte[] requestBody = exchange.getRequestBody().readAllBytes();
            byte[] responseBody;
            int status = 200;
            try {
                responseBody = handler.handle(requestBody);
            } catch (Exception e) {
                responseBody = new byte[0];
                status = 500;
            }
            exchange.getResponseHeaders().add("Content-Type", contentType);
            exchange.sendResponseHeaders(status, responseBody.length == 0 ? -1 : responseBody.length);
            try (OutputStream os = exchange.getResponseBody()) {
                if (responseBody.length > 0) {
                    os.write(responseBody);
                }
            }
        });
    }

    public void respondAfterDelay(String path, Duration delay, int status, String contentType, byte[] body) {
        server.createContext(path, exchange -> {
            try {
                Thread.sleep(delay.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.getResponseHeaders().add("Content-Type", contentType);
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                if (body.length > 0) {
                    os.write(body);
                }
            }
        });
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
