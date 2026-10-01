package com.coam.pdfvalidator.infrastructure.revocation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A minimal, deliberately non-redirecting HTTP/1.1 client used only for
 * OCSP/CRL requests, built on a plain {@link Socket} instead of {@code
 * java.net.http.HttpClient}.
 *
 * <p><b>Why not {@code java.net.http.HttpClient}</b>: it re-resolves the
 * target hostname itself at connect time, which happens <em>after</em> --
 * and independently of -- whatever validation {@link RevocationUrlGuard}
 * already performed on that same hostname. A hostile authoritative DNS
 * server can answer those two lookups differently (a public address for
 * the validating lookup, a private one moments later for the real
 * connection): classic DNS-rebinding SSRF, and {@code HttpClient} exposes
 * no supported way to pin a specific resolved address for a request in
 * this JDK. This class instead takes the exact {@link
 * RevocationUrlGuard.ValidatedTarget} the guard already resolved and
 * connects a socket to its {@code InetAddress} directly -- the hostname is
 * never looked up again.
 *
 * <p><b>Only {@code http} is supported</b> (enforced by {@link
 * RevocationUrlGuard#resolve} rejecting any other scheme before this class
 * ever runs). Correctly pinning {@code https} the same way would require
 * connecting a raw {@code Socket} to the pinned address and then layering
 * TLS on top with {@code SSLSocketFactory#createSocket(Socket, String, int,
 * boolean)} so SNI/hostname verification keeps checking the
 * <em>original</em> hostname -- technically possible, but judged out of
 * proportion for this task's scope (revocation checking is optional,
 * best-effort and already bounded to a couple of seconds): every CA this
 * project has tested against (FNMT, Camerfirma) publishes OCSP/CRL over
 * plain {@code http://}, which matches common CA practice (the signed
 * response carries the trust, not the transport). An {@code https://}
 * AIA/CDP URL is rejected upstream with a clear {@code UNKNOWN} reason
 * instead of a fragile or partially-correct TLS implementation.
 *
 * <p>Never follows redirects (there is no redirect-following code at all),
 * and enforces both a connect/read deadline and a response size cap.
 * Supports {@code Content-Length}-framed and {@code chunked} responses
 * (the two framings real-world OCSP/CRL responders actually use); any other
 * framing is rejected.
 */
final class PinnedHttpClient {

    private PinnedHttpClient() {
    }

    record Response(int statusCode, byte[] body) {
    }

    /**
     * Caps on the response head, so a hostile responder cannot make this
     * server buffer arbitrarily large header or chunk-trailer blocks within
     * the time limit: {@code maxLineBytes} bounds every single line (status
     * line, header, chunk-size line, trailer), {@code maxHeaderCount} the
     * number of header (or, separately, trailer) lines and {@code
     * maxHeaderBytes} their combined size. Exceeding any of them is a
     * {@link MalformedHttpResponseException} (mapped to {@code UNKNOWN}).
     */
    record Limits(int maxLineBytes, int maxHeaderCount, int maxHeaderBytes) {

        static final Limits DEFAULT = new Limits(8 * 1024, 100, 64 * 1024);

        Limits {
            if (maxLineBytes < 1 || maxHeaderCount < 1 || maxHeaderBytes < 1) {
                throw new IllegalArgumentException("header limits must be positive");
            }
        }
    }

    /**
     * Sends one request to {@code target.address()} (never re-resolving
     * {@code target.uri()}'s hostname), with a {@code Host} header carrying
     * the original hostname so name-based virtual hosting still works.
     *
     * @throws IOException              on a network/protocol failure (including a timeout, surfaced as
     *                                   {@link SocketTimeoutException}) or an unsupported response framing
     * @throws ResponseTooLargeException if the body exceeds {@code maxResponseBytes}
     */
    static Response send(
            RevocationUrlGuard.ValidatedTarget target, String method, byte[] requestBody,
            Map<String, String> extraHeaders, Duration timeout, long maxResponseBytes) throws IOException {
        return send(target, method, requestBody, extraHeaders, timeout, maxResponseBytes, Limits.DEFAULT);
    }

    /** Same as above, with explicit {@link Limits} on the response head. */
    static Response send(
            RevocationUrlGuard.ValidatedTarget target, String method, byte[] requestBody,
            Map<String, String> extraHeaders, Duration timeout, long maxResponseBytes, Limits limits)
            throws IOException {

        String host = target.uri().getHost();
        int port = target.uri().getPort() != -1 ? target.uri().getPort() : 80;
        String path = target.uri().getRawPath() == null || target.uri().getRawPath().isEmpty()
                ? "/" : target.uri().getRawPath();
        if (target.uri().getRawQuery() != null) {
            path = path + "?" + target.uri().getRawQuery();
        }

        // The absolute deadline is computed BEFORE connecting, and governs the connect timeout
        // too, so a slow server can no longer take up to ~2x the configured timeout by stalling
        // the connect+write phase before the read-side deadline was ever started.
        long deadlineNanos = System.nanoTime() + timeout.toNanos();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target.address(), port), remainingMillisOrThrow(deadlineNanos));
            adjustSoTimeout(socket, deadlineNanos);

            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Host", port == 80 ? host : host + ":" + port);
            headers.put("Connection", "close");
            headers.putAll(extraHeaders);
            if (requestBody != null && requestBody.length > 0) {
                headers.put("Content-Length", String.valueOf(requestBody.length));
            }

            writeRequest(socket.getOutputStream(), method, path, headers, requestBody);

            return readResponse(socket, deadlineNanos, maxResponseBytes, limits);
        }
    }

    private static void writeRequest(
            OutputStream out, String method, String path, Map<String, String> headers, byte[] body)
            throws IOException {
        StringBuilder request = new StringBuilder();
        request.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
        request.append("\r\n");
        out.write(request.toString().getBytes(StandardCharsets.US_ASCII));
        if (body != null && body.length > 0) {
            out.write(body);
        }
        out.flush();
    }

    // The stream is owned by the socket, which the caller (send) closes with try-with-resources.
    @SuppressWarnings("PMD.CloseResource")
    private static Response readResponse(Socket socket, long deadlineNanos, long maxResponseBytes, Limits limits)
            throws IOException {
        InputStream in = socket.getInputStream();

        String statusLine = readLine(in, socket, deadlineNanos, limits.maxLineBytes());
        if (statusLine == null || !statusLine.startsWith("HTTP/1.")) {
            throw new MalformedHttpResponseException("malformed HTTP status line");
        }
        String[] statusParts = statusLine.split(" ", 3);
        if (statusParts.length < 2) {
            throw new MalformedHttpResponseException("malformed HTTP status line: missing status code");
        }
        int statusCode;
        try {
            statusCode = Integer.parseInt(statusParts[1]);
        } catch (NumberFormatException e) {
            throw new MalformedHttpResponseException("malformed HTTP status line: non-numeric status code", e);
        }

        Map<String, String> responseHeaders = new LinkedHashMap<>();
        HeaderBudget headerBudget = new HeaderBudget(limits, "header");
        String line;
        while ((line = readLine(in, socket, deadlineNanos, limits.maxLineBytes())) != null && !line.isEmpty()) {
            headerBudget.charge(line);
            int colon = line.indexOf(':');
            if (colon > 0) {
                responseHeaders.put(line.substring(0, colon).trim().toLowerCase(java.util.Locale.ROOT),
                        line.substring(colon + 1).trim());
            }
        }

        byte[] body = readBody(in, responseHeaders, maxResponseBytes, deadlineNanos, socket, limits);
        return new Response(statusCode, body);
    }

    private static byte[] readBody(
            InputStream in, Map<String, String> headers, long maxResponseBytes, long deadlineNanos, Socket socket,
            Limits limits) throws IOException {
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null && transferEncoding.toLowerCase(java.util.Locale.ROOT).contains("chunked")) {
            return readChunkedBody(in, maxResponseBytes, deadlineNanos, socket, limits);
        }

        String contentLengthHeader = headers.get("content-length");
        if (contentLengthHeader == null) {
            throw new MalformedHttpResponseException(
                    "unsupported response framing (no Content-Length or chunked Transfer-Encoding)");
        }
        long contentLength;
        try {
            contentLength = Long.parseLong(contentLengthHeader.trim());
        } catch (NumberFormatException e) {
            throw new MalformedHttpResponseException("malformed Content-Length header", e);
        }
        if (contentLength < 0) {
            throw new MalformedHttpResponseException("negative Content-Length");
        }
        if (contentLength > maxResponseBytes) {
            throw new ResponseTooLargeException();
        }
        byte[] body = new byte[Math.toIntExact(contentLength)];
        int read = 0;
        while (read < body.length) {
            adjustSoTimeout(socket, deadlineNanos);
            int n = in.read(body, read, body.length - read);
            if (n < 0) {
                throw new IOException("connection closed before the declared Content-Length was read");
            }
            read += n;
        }
        return body;
    }

    private static byte[] readChunkedBody(
            InputStream in, long maxResponseBytes, long deadlineNanos, Socket socket, Limits limits)
            throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in, socket, deadlineNanos, limits.maxLineBytes());
            if (sizeLine == null) {
                throw new IOException("connection closed while reading a chunk size");
            }
            int semicolon = sizeLine.indexOf(';');
            String hex = (semicolon >= 0 ? sizeLine.substring(0, semicolon) : sizeLine).trim();
            int chunkSize;
            try {
                chunkSize = Integer.parseInt(hex, 16);
            } catch (NumberFormatException e) {
                throw new MalformedHttpResponseException("malformed chunk size", e);
            }
            if (chunkSize < 0) {
                throw new MalformedHttpResponseException("negative chunk size");
            }
            if (chunkSize == 0) {
                // Trailing headers (if any), then the final blank line.
                HeaderBudget trailerBudget = new HeaderBudget(limits, "trailer");
                String trailer;
                while ((trailer = readLine(in, socket, deadlineNanos, limits.maxLineBytes())) != null
                        && !trailer.isEmpty()) {
                    trailerBudget.charge(trailer); // discarded, but still bounded
                }
                break;
            }
            // long arithmetic: int addition could overflow to a negative total
            // and let a huge chunk through the cap.
            if ((long) buffer.size() + chunkSize > maxResponseBytes) {
                throw new ResponseTooLargeException();
            }
            byte[] chunk = new byte[chunkSize];
            int read = 0;
            while (read < chunkSize) {
                adjustSoTimeout(socket, deadlineNanos);
                int n = in.read(chunk, read, chunkSize - read);
                if (n < 0) {
                    throw new IOException("connection closed while reading a chunk body");
                }
                read += n;
            }
            buffer.write(chunk, 0, chunk.length);
            readLine(in, socket, deadlineNanos, limits.maxLineBytes()); // trailing CRLF after each chunk's data
        }
        return buffer.toByteArray();
    }

    private static int remainingMillisOrThrow(long deadlineNanos) throws SocketTimeoutException {
        long remainingMillis = (deadlineNanos - System.nanoTime()) / 1_000_000;
        if (remainingMillis <= 0) {
            throw new SocketTimeoutException("revocation request exceeded its overall timeout");
        }
        return Math.toIntExact(Math.min(remainingMillis, Integer.MAX_VALUE));
    }

    private static void adjustSoTimeout(Socket socket, long deadlineNanos) throws IOException {
        socket.setSoTimeout(remainingMillisOrThrow(deadlineNanos));
    }

    /**
     * Reads one CRLF-terminated line, re-checking the overall deadline before EVERY individual
     * byte read (not just once before the call) -- otherwise a responder trickling one byte just
     * under each read's own socket timeout can keep a single {@code readLine} call (a status
     * line, a header line, a chunk-trailer line, ...) alive far past the configured deadline.
     */
    private static String readLine(InputStream in, Socket socket, long deadlineNanos, int maxLineBytes)
            throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int previous = -1;
        while (true) {
            adjustSoTimeout(socket, deadlineNanos);
            int current = in.read();
            if (current == -1) {
                return line.size() == 0 ? null : new String(line.toByteArray(), StandardCharsets.US_ASCII);
            }
            if (previous == '\r' && current == '\n') {
                byte[] bytes = line.toByteArray();
                return new String(bytes, 0, bytes.length - 1, StandardCharsets.US_ASCII);
            }
            line.write(current);
            if (line.size() > maxLineBytes) {
                throw new MalformedHttpResponseException("HTTP line exceeds the size limit");
            }
            previous = current;
        }
    }

    /** Counts the lines and bytes of one header (or trailer) block against {@link Limits}. */
    private static final class HeaderBudget {
        private final Limits limits;
        private final String kind;
        private int count;
        private long bytes;

        HeaderBudget(Limits limits, String kind) {
            this.limits = limits;
            this.kind = kind;
        }

        void charge(String line) throws MalformedHttpResponseException {
            count++;
            bytes += line.length() + 2L;
            if (count > limits.maxHeaderCount()) {
                throw new MalformedHttpResponseException("too many HTTP " + kind + " lines");
            }
            if (bytes > limits.maxHeaderBytes()) {
                throw new MalformedHttpResponseException("HTTP " + kind + " block exceeds the size limit");
            }
        }
    }

    /** Thrown when a response's HTTP framing cannot be parsed safely; mapped to {@code UNKNOWN} by the caller. */
    static final class MalformedHttpResponseException extends IOException {
        MalformedHttpResponseException(String message) {
            super(message);
        }

        MalformedHttpResponseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when a response body exceeds the configured size cap; mapped to {@code UNKNOWN} by the caller. */
    static final class ResponseTooLargeException extends IOException {
        ResponseTooLargeException() {
            super("response exceeds the size limit");
        }
    }
}
