package com.coam.pdfvalidator.infrastructure.revocation;

import com.coam.pdfvalidator.fixtures.RawSocketTestServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * {@link PinnedHttpClient} against a raw {@link RawSocketTestServer}: proves
 * the overall deadline is enforced on every individual read (not just once
 * per phase), and that malformed/hostile framing is rejected as a checked
 * {@link PinnedHttpClient.MalformedHttpResponseException} rather than an
 * unchecked parse-failure exception (R3-header-phase-deadline-bypass,
 * R3-unchecked-parse-escapes).
 */
class PinnedHttpClientTest {

    private RawSocketTestServer server;

    @BeforeEach
    void startServer() throws Exception {
        server = RawSocketTestServer.start();
    }

    @AfterEach
    void stopServer() throws Exception {
        server.close();
    }

    private RevocationUrlGuard.ValidatedTarget target() throws Exception {
        return new RevocationUrlGuard.ValidatedTarget(
                URI.create(server.baseUrl() + "/x"), InetAddress.getByName("127.0.0.1"));
    }

    /** Splits {@code text} into one-byte chunks, to trickle a response past a per-read (not overall) deadline. */
    private static List<byte[]> byteByByte(String text) {
        List<byte[]> chunks = new ArrayList<>();
        for (byte b : text.getBytes(StandardCharsets.US_ASCII)) {
            chunks.add(new byte[] {b});
        }
        return chunks;
    }

    private void assertTimesOutWithinTheOverallDeadline(long timeoutMillis) {
        long start = System.nanoTime();
        assertTimeoutPreemptively(Duration.ofSeconds(5), () ->
                assertThatThrownBy(() -> PinnedHttpClient.send(
                        target(), "GET", null, Map.of(), Duration.ofMillis(timeoutMillis), 1024))
                        .isInstanceOf(SocketTimeoutException.class));
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
        // Tighter than the "at most timeout*2" floor: an overall deadline enforced on every
        // read must abort close to the deadline itself, not merely before some later, looser
        // bound -- a per-phase (rather than per-read) check can still slip well past timeout*2.
        assertThat(elapsedMillis).isLessThan(timeoutMillis + 300);
    }

    @Test
    void aStatusLineTrickledOneByteAtATimeTimesOutWithinTheOverallDeadline() {
        server.respondWithChunks(byteByByte("HTTP/1.1 200 OK\r\n\r\n"), 60);
        assertTimesOutWithinTheOverallDeadline(500);
    }

    @Test
    void headersTrickledOneByteAtATimeTimeOutWithinTheOverallDeadline() {
        List<byte[]> chunks = new ArrayList<>();
        chunks.add("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.US_ASCII));
        chunks.addAll(byteByByte("X-Slow: header\r\n\r\n"));
        server.respondWithChunks(chunks, 60);
        assertTimesOutWithinTheOverallDeadline(500);
    }

    @Test
    void aChunkTrailerTrickledOneByteAtATimeTimesOutWithinTheOverallDeadline() {
        List<byte[]> chunks = new ArrayList<>();
        chunks.add(("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        chunks.addAll(byteByByte("X-Trailer: v\r\n\r\n"));
        server.respondWithChunks(chunks, 60);
        assertTimesOutWithinTheOverallDeadline(500);
    }

    private void assertMalformed(String rawResponse) {
        server.respondWithChunks(List.of(rawResponse.getBytes(StandardCharsets.US_ASCII)), 0);
        assertThatThrownBy(() -> PinnedHttpClient.send(
                target(), "GET", null, Map.of(), Duration.ofSeconds(2), 1024))
                .isInstanceOf(PinnedHttpClient.MalformedHttpResponseException.class);
    }

    @Test
    void aStatusLineWithoutASpaceIsAMalformedResponseNotAnUncheckedException() {
        assertMalformed("HTTP/1.1\r\n\r\n");
    }

    @Test
    void aNonNumericStatusCodeIsAMalformedResponse() {
        assertMalformed("HTTP/1.1 XX OK\r\n\r\n");
    }

    @Test
    void aNonNumericContentLengthIsAMalformedResponse() {
        assertMalformed("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nbody");
    }

    @Test
    void aNegativeContentLengthIsAMalformedResponse() {
        assertMalformed("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n");
    }

    @Test
    void aNonHexChunkSizeIsAMalformedResponse() {
        assertMalformed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n");
    }

    @Test
    void aNegativeChunkSizeIsAMalformedResponse() {
        assertMalformed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n");
    }

    @Test
    void aChunkSizeThatOverflowsTheRunningTotalIsRejectedAsTooLargeInsteadOfAllocating() {
        // 1 + 0x7FFFFFFF overflows int: the size cap must be checked in long
        // arithmetic, otherwise a ~2 GiB array is allocated (OutOfMemoryError).
        server.respondWithChunks(List.of(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n7FFFFFFF\r\n"
                        .getBytes(StandardCharsets.US_ASCII)), 0);
        assertThatThrownBy(() -> PinnedHttpClient.send(
                target(), "GET", null, Map.of(), Duration.ofSeconds(2), 1024))
                .isInstanceOf(PinnedHttpClient.ResponseTooLargeException.class);
    }
}
