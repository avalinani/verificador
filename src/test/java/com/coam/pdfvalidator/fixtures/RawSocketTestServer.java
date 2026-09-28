package com.coam.pdfvalidator.fixtures;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * A raw, byte-level loopback HTTP test server for protocol-edge-case tests
 * (deadline enforcement while trickling bytes, malformed framing) that
 * {@code com.sun.net.httpserver.HttpServer} cannot produce on its own since
 * it always emits well-formed responses. Never use this in production code.
 */
public final class RawSocketTestServer implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private RawSocketTestServer(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    public static RawSocketTestServer start() throws IOException {
        return new RawSocketTestServer(new ServerSocket(0, 0, InetAddress.getLoopbackAddress()));
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + port();
    }

    /**
     * Accepts one connection (in a background thread) and writes each
     * element of {@code chunks} in order, sleeping {@code delayMillis}
     * before each one -- used to trickle a response one byte at a time to
     * prove a per-read (rather than overall) deadline can be defeated.
     */
    public void respondWithChunks(List<byte[]> chunks, long delayMillis) {
        executor.submit(() -> {
            try (Socket socket = serverSocket.accept(); OutputStream out = socket.getOutputStream()) {
                // Drain the client's request first: closing this socket while its receive
                // buffer still holds unread bytes can make some TCP stacks (Windows in
                // particular) send an RST instead of a graceful FIN, which can then surface as
                // a spurious SocketException on the client side even for bytes it already read.
                drainRequest(socket.getInputStream());
                for (byte[] chunk : chunks) {
                    if (delayMillis > 0) {
                        Thread.sleep(delayMillis);
                    }
                    out.write(chunk);
                    out.flush();
                }
            } catch (Exception e) {
                // Best effort: the calling test's assertion on the client side covers failure.
            }
        });
    }

    /** Reads until the request's terminating blank line; these tests only ever send bodyless GETs. */
    private static void drainRequest(InputStream in) throws IOException {
        int previous = -1;
        int beforePrevious = -1;
        int current;
        while ((current = in.read()) != -1) {
            if (beforePrevious == '\r' && previous == '\n' && current == '\r') {
                in.read();
                return;
            }
            beforePrevious = previous;
            previous = current;
        }
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        executor.shutdownNow();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
