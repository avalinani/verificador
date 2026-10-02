package com.coam.pdfvalidator.tools.tsl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Downloads a trusted list: HTTPS only (standard JDK PKIX certificate and
 * host name validation, redirects not followed), connect/response/body
 * timeouts and a {@value #MAX_BYTES}-byte cap (the ES TSL is about 3 MB).
 *
 * <p>The TLS trust is the JDK's default {@code cacerts} plus exactly one
 * pinned root, AC RAIZ FNMT-RCM: {@code tsl.digital.gob.es} is served under
 * it and the JDK does not ship it. TLS is defence in depth here; what makes a
 * list trusted is its own XML signature, checked against pinned signers.
 */
final class HttpsFetcher implements TslSync.Fetcher {

    /** AC RAIZ FNMT-RCM, downloaded from sede.fnmt.gob.es; this fingerprint matches its CCADB record. */
    static final String FNMT_ROOT_SHA256 = "ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa";
    private static final String FNMT_ROOT_RESOURCE = "tls-root-ac-raiz-fnmt-rcm.crt";
    static final int MAX_BYTES = 20 * 1024 * 1024;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration RESPONSE_TIMEOUT = Duration.ofSeconds(60);
    private static final Duration BODY_TIMEOUT = Duration.ofSeconds(120);

    private final HttpClient client;

    HttpsFetcher() {
        client = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(tlsContext())
                .build();
    }

    /** The JDK default trust anchors plus the pinned FNMT root. */
    static List<X509Certificate> tlsTrustAnchors() {
        try {
            TrustManagerFactory defaults = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            defaults.init((KeyStore) null);
            List<X509Certificate> anchors = new ArrayList<>();
            for (TrustManager manager : defaults.getTrustManagers()) {
                if (manager instanceof X509TrustManager x509) {
                    anchors.addAll(List.of(x509.getAcceptedIssuers()));
                }
            }
            anchors.add(fnmtRoot());
            return anchors;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Cannot build the TLS trust for the trusted list downloads", e);
        }
    }

    private static X509Certificate fnmtRoot() throws IOException, GeneralSecurityException {
        try (InputStream in = HttpsFetcher.class.getResourceAsStream(FNMT_ROOT_RESOURCE)) {
            if (in == null) {
                throw new IOException("Missing TLS root resource " + FNMT_ROOT_RESOURCE);
            }
            X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            if (!FNMT_ROOT_SHA256.equals(Fingerprints.sha256(root))) {
                throw new GeneralSecurityException("The bundled FNMT TLS root does not match its pinned SHA-256");
            }
            return root;
        }
    }

    private static SSLContext tlsContext() {
        try {
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            int alias = 0;
            for (X509Certificate anchor : tlsTrustAnchors()) {
                trust.setCertificateEntry("anchor-" + alias++, anchor);
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
            factory.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Cannot build the TLS context for the trusted list downloads", e);
        }
    }

    @Override
    public byte[] fetch(URI uri) throws IOException {
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IOException("Only HTTPS downloads are allowed: " + uri);
        }
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(RESPONSE_TIMEOUT)
                .header("Accept", "application/vnd.etsi.tsl+xml, application/xml, text/xml")
                .GET()
                .build();
        HttpResponse<InputStream> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while downloading " + uri, e);
        }
        try (InputStream body = response.body()) {
            if (response.statusCode() != 200) {
                throw new IOException("GET " + uri + " returned HTTP " + response.statusCode());
            }
            return readCapped(uri, body);
        }
    }

    /** Reads at most {@link #MAX_BYTES} within {@link #BODY_TIMEOUT}; a stalled body is aborted by closing it. */
    private static byte[] readCapped(URI uri, InputStream body) throws IOException {
        try (ExecutorService reader = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<byte[]> read = reader.submit(() -> body.readNBytes(MAX_BYTES + 1));
            byte[] data;
            try {
                data = read.get(BODY_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                body.close();
                read.cancel(true);
                throw new IOException("Timed out reading " + uri, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                body.close();
                throw new IOException("Interrupted while reading " + uri, e);
            } catch (ExecutionException e) {
                throw new IOException("Could not read " + uri, e.getCause());
            }
            if (data.length > MAX_BYTES) {
                throw new IOException(uri + " is larger than the " + MAX_BYTES + "-byte cap");
            }
            return data;
        }
    }
}
