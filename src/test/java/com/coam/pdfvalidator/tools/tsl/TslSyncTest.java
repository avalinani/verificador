package com.coam.pdfvalidator.tools.tsl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.stream.Stream;

import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.CA_QC;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.FOR_E_SEALS;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.GRANTED;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.NOW;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.SigningKey;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.TSA_QTST;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.TSL_MIME;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.certificate;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.lotl;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.pointer;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.provider;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.service;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.sha256;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.sign;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.signingKey;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.tsl;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End to end, offline: a pinned LOTL points to the ES TSL and announces its
 * signer; the ES TSL's selected services become the bundled trust store.
 */
class TslSyncTest {

    private static final URI LOTL_URL = URI.create("https://lotl.example.test/eu-lotl.xml");
    private static final URI TSL_URL = URI.create("https://tsl.example.test/TSL.xml");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static final SigningKey LOTL_SIGNER = signingKey("LOTL signer");
    private static final SigningKey TSL_SIGNER = signingKey("ES scheme operator");
    private static final X509Certificate SIGNATURE_CA = certificate("Signature CA");
    private static final X509Certificate TSA = certificate("TSA unit");

    private static final byte[] ES_TSL = sign(tsl(189, NOW.plus(Duration.ofDays(150)),
            provider("Fábrica Test",
                    service("AC Usuarios", CA_QC, GRANTED, List.of(), List.of(), SIGNATURE_CA),
                    service("AC Sellos", CA_QC, GRANTED, List.of(FOR_E_SEALS), List.of(), certificate("Seal CA")),
                    service("Sello de tiempo", TSA_QTST, GRANTED, List.of(), List.of(), TSA))), TSL_SIGNER);

    private static byte[] lotlPointingTo(String location, X509Certificate... tslSigners) {
        return sign(lotl(395, NOW.plus(Duration.ofDays(170)),
                pointer("https://tsl.example.test/TSL.pdf", "ES", "application/pdf", tslSigners),
                pointer(location, "ES", TSL_MIME, tslSigners),
                pointer("https://other.example.test/tsl.xml", "FR", TSL_MIME, certificate("FR operator"))),
                LOTL_SIGNER);
    }

    private static TslSync sync(Map<URI, byte[]> responses) {
        return new TslSync(uri -> {
            byte[] body = responses.get(uri);
            if (body == null) {
                throw new IOException("unexpected download " + uri);
            }
            return body;
        }, CLOCK, LOTL_URL, Set.of(sha256(LOTL_SIGNER.certificate())));
    }

    private static Map<URI, byte[]> healthyResponses() {
        Map<URI, byte[]> responses = new HashMap<>();
        responses.put(LOTL_URL, lotlPointingTo(TSL_URL.toString(), TSL_SIGNER.certificate()));
        responses.put(TSL_URL, ES_TSL);
        return responses;
    }

    @Test
    void generatesTheTrustStoreFromTheVerifiedLotlAndEsTsl() throws Exception {
        TslSync.Result result = sync(healthyResponses()).generate();
        SortedMap<String, String> files = result.files();

        assertThat(result.anchors()).extracting(Anchor::sha256)
                .containsExactlyInAnyOrder(sha256(SIGNATURE_CA), sha256(TSA));
        List<String> certificateFiles = files.keySet().stream().filter(name -> name.endsWith(".crt")).toList();
        assertThat(certificateFiles).hasSize(2);
        assertThat(files).containsKeys("index.txt", "SOURCES.md");
        assertThat(files.get("index.txt").lines().filter(line -> !line.startsWith("#")).toList())
                .containsExactlyElementsOf(certificateFiles);
        for (String name : certificateFiles) {
            X509Certificate parsed = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(
                            files.get(name).getBytes(StandardCharsets.US_ASCII)));
            assertThat(name).contains(sha256(parsed).substring(0, 12));
            assertThat(files.get(name)).startsWith("-----BEGIN CERTIFICATE-----\n");
        }
        String sources = files.get("SOURCES.md");
        assertThat(sources)
                .contains(LOTL_URL.toString(), TSL_URL.toString(), "395", "189",
                        sha256(LOTL_SIGNER.certificate()), sha256(TSL_SIGNER.certificate()),
                        sha256(SIGNATURE_CA), sha256(TSA), "Fábrica Test", "AC Usuarios", "Sello de tiempo",
                        "ForeSignatures", "QCForESig", "granted")
                .doesNotContain("AC Sellos");
    }

    @Test
    void producesByteIdenticalOutputWhenTheListsHaveNotChanged() throws Exception {
        Map<URI, byte[]> responses = healthyResponses();

        SortedMap<String, String> first = sync(responses).generate().files();
        SortedMap<String, String> second = new TslSync(uri -> responses.get(uri),
                Clock.fixed(NOW.plus(Duration.ofDays(3)), ZoneOffset.UTC), LOTL_URL,
                Set.of(sha256(LOTL_SIGNER.certificate()))).generate().files();

        assertThat(second).isEqualTo(first);
    }

    @Test
    void rejectsAnEsTslSignedByACertificateTheLotlDoesNotAnnounce() {
        Map<URI, byte[]> responses = healthyResponses();
        responses.put(LOTL_URL, lotlPointingTo(TSL_URL.toString(), certificate("Announced operator")));

        assertThatThrownBy(() -> sync(responses).generate())
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("not pinned");
    }

    @Test
    void rejectsALotlSignedByACertificateThatIsNotPinnedWithAHintToUpdateThePins() {
        Map<URI, byte[]> responses = healthyResponses();
        responses.put(LOTL_URL, sign(lotl(395, NOW.plus(Duration.ofDays(170)),
                pointer(TSL_URL.toString(), "ES", TSL_MIME, TSL_SIGNER.certificate())), signingKey("Rotated")));

        assertThatThrownBy(() -> sync(responses).generate())
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("not pinned")
                .hasMessageContaining("Official Journal");
    }

    @Test
    void rejectsAnEsTslLocationThatIsNotHttps() {
        Map<URI, byte[]> responses = healthyResponses();
        responses.put(LOTL_URL, lotlPointingTo("http://tsl.example.test/TSL.xml", TSL_SIGNER.certificate()));

        assertThatThrownBy(() -> sync(responses).generate())
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("HTTPS");
    }

    @Test
    void rejectsALotlWithoutAnEsTslPointer() {
        Map<URI, byte[]> responses = healthyResponses();
        responses.put(LOTL_URL, sign(lotl(395, NOW.plus(Duration.ofDays(170)),
                pointer("https://other.example.test/tsl.xml", "FR", TSL_MIME, certificate("FR operator"))),
                LOTL_SIGNER));

        assertThatThrownBy(() -> sync(responses).generate())
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("ES");
    }

    @Test
    void replacesTheWholeTrustStoreDirectory(@TempDir Path parent) throws Exception {
        Path truststore = Files.createDirectory(parent.resolve("truststore"));
        Files.writeString(truststore.resolve("hand-curated-root.pem"), "old");
        Files.writeString(truststore.resolve("SOURCES.md"), "old");

        sync(healthyResponses()).run(truststore);

        SortedMap<String, String> expected = sync(healthyResponses()).generate().files();
        try (Stream<Path> entries = Files.list(truststore)) {
            assertThat(entries.map(path -> path.getFileName().toString()).sorted().toList())
                    .containsExactlyElementsOf(expected.keySet());
        }
        for (Map.Entry<String, String> file : expected.entrySet()) {
            assertThat(truststore.resolve(file.getKey())).hasContent(file.getValue());
        }
        try (Stream<Path> siblings = Files.list(parent)) {
            assertThat(siblings).containsExactly(truststore);
        }
    }

    @Test
    void leavesTheTrustStoreUntouchedWhenAnythingFails(@TempDir Path parent) throws Exception {
        Path truststore = Files.createDirectory(parent.resolve("truststore"));
        Files.writeString(truststore.resolve("existing.crt"), "keep me");
        Map<URI, byte[]> responses = healthyResponses();
        responses.remove(TSL_URL);

        assertThatThrownBy(() -> sync(responses).run(truststore)).isInstanceOf(IOException.class);

        try (Stream<Path> entries = Files.list(truststore)) {
            assertThat(entries).containsExactly(truststore.resolve("existing.crt"));
        }
        assertThat(truststore.resolve("existing.crt")).hasContent("keep me");
    }

    @Test
    void pinsTheSixLotlSignerCertificatesAnnouncedInTheOfficialJournal() {
        assertThat(TslSync.LOTL_SIGNER_SHA256).hasSize(6)
                .allMatch(pin -> pin.matches("[0-9a-f]{64}"))
                .contains("e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1");
        assertThat(TslSync.LOTL_URL).hasToString("https://ec.europa.eu/tools/lotl/eu-lotl.xml");
    }
}
