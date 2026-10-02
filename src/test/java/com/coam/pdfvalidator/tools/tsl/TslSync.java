package com.coam.pdfvalidator.tools.tsl;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.stream.Collectors;

/**
 * Maintainer tool (never part of the runtime jar): regenerates the bundled
 * trust store {@code src/main/resources/truststore/} from the official EU
 * trusted lists.
 *
 * <ol>
 *   <li>Download the EU List of Trusted Lists (LOTL) and verify its
 *       signature against the signer certificates announced in the Official
 *       Journal ({@link #LOTL_SIGNER_SHA256}).</li>
 *   <li>Follow the LOTL's pointer to the Spanish TSL and verify that list's
 *       signature against the certificates the verified LOTL announces for
 *       it.</li>
 *   <li>Select the anchors ({@link AnchorSelector}), render the directory
 *       ({@link TrustStoreRenderer}) and only then replace it
 *       ({@link TrustStoreWriter}).</li>
 * </ol>
 * Any failure aborts before the directory is touched.
 *
 * <p>Run it with {@code ./mvnw -q -Ptsl-sync} (see the README).
 */
public final class TslSync {

    static final URI LOTL_URL = URI.create("https://ec.europa.eu/tools/lotl/eu-lotl.xml");

    /**
     * SHA-256 of the six LOTL signer certificates announced by the European
     * Commission in the Official Journal, OJ C/2026/1944. Copied from the
     * LOTL's own first {@code OtherTSLPointer} (the pointer to itself) on
     * 2026-10-01; the maintainer must cross-check them once against the OJ
     * publication on EUR-Lex. When the Commission rotates its signers, a new
     * OJ notice announces them: update this set from it.
     */
    static final Set<String> LOTL_SIGNER_SHA256 = Set.of(
            "d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
            "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
            "c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
            "df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
            "b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
            "236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b");

    static final String TSL_MIME_TYPE = "application/vnd.etsi.tsl+xml";
    private static final String TERRITORY = "ES";

    /** Downloads one list; the real implementation is {@link HttpsFetcher}, tests pass canned bytes. */
    @FunctionalInterface
    interface Fetcher {
        byte[] fetch(URI uri) throws IOException;
    }

    /** The rendered directory plus what it was built from. */
    record Result(SortedMap<String, String> files, List<Anchor> anchors, VerifiedTrustedList lotl,
                  VerifiedTrustedList tsl) {
    }

    private final Fetcher fetcher;
    private final Clock clock;
    private final URI lotlUrl;
    private final Set<String> lotlPins;

    TslSync(Fetcher fetcher, Clock clock, URI lotlUrl, Set<String> lotlPins) {
        this.fetcher = fetcher;
        this.clock = clock;
        this.lotlUrl = lotlUrl;
        this.lotlPins = Set.copyOf(lotlPins);
    }

    /** Downloads and verifies both lists and renders the trust store in memory, without writing anything. */
    Result generate() throws IOException, TrustedListException {
        Instant now = clock.instant();
        VerifiedTrustedList lotl;
        try {
            lotl = TrustedListLoader.load(lotlUrl, fetcher.fetch(lotlUrl), lotlPins, now);
        } catch (UnpinnedSignerException e) {
            throw new TrustedListException("The LOTL signer certificate " + e.signerSha256() + " is not pinned. "
                    + "The European Commission has probably rotated its signing certificates: take the new "
                    + "ones from the Official Journal notice that announces them and update "
                    + "TslSync.LOTL_SIGNER_SHA256.", e);
        }
        requireTerritory(lotl, "EU");

        TrustedListPointer pointer = spanishTslPointer(lotl.list());
        URI tslUrl = URI.create(pointer.location());
        if (!"https".equalsIgnoreCase(tslUrl.getScheme())) {
            throw new TrustedListException("The LOTL points to the ES TSL over a non-HTTPS URL: " + tslUrl);
        }
        Set<String> tslPins = pointer.certificates().stream().map(Fingerprints::sha256).collect(Collectors.toSet());
        if (tslPins.isEmpty()) {
            throw new TrustedListException("The LOTL announces no signer certificate for the ES TSL");
        }
        VerifiedTrustedList tsl = TrustedListLoader.load(tslUrl, fetcher.fetch(tslUrl), tslPins, now);
        requireTerritory(tsl, TERRITORY);

        List<Anchor> anchors = AnchorSelector.select(tsl.list().services(), now);
        if (anchors.isEmpty()) {
            throw new TrustedListException("The ES TSL yielded no anchor at all; refusing to empty the trust store");
        }
        return new Result(TrustStoreRenderer.render(lotl, tsl, anchors), anchors, lotl, tsl);
    }

    /** {@link #generate()}, then replace {@code truststore} with the result. */
    Result run(Path truststore) throws IOException, TrustedListException {
        Result result = generate();
        TrustStoreWriter.replace(truststore, result.files());
        return result;
    }

    private static TrustedListPointer spanishTslPointer(TrustedList lotl) throws TrustedListException {
        List<TrustedListPointer> matches = lotl.pointers().stream()
                .filter(pointer -> TERRITORY.equals(pointer.territory()) && TSL_MIME_TYPE.equals(pointer.mimeType()))
                .toList();
        if (matches.size() != 1) {
            throw new TrustedListException("Expected exactly one LOTL pointer to the ES TSL (" + TSL_MIME_TYPE
                    + "), found " + matches.size());
        }
        return matches.getFirst();
    }

    private static void requireTerritory(VerifiedTrustedList verified, String territory) throws TrustedListException {
        if (!territory.equals(verified.list().territory())) {
            throw new TrustedListException(verified.source() + " has SchemeTerritory "
                    + verified.list().territory() + ", expected " + territory);
        }
    }

    /**
     * Entry point of {@code ./mvnw -q -Ptsl-sync}.
     *
     * @param args optional: the trust store directory (default {@code src/main/resources/truststore})
     */
    public static void main(String[] args) throws IOException, TrustedListException {
        Path truststore = Path.of(args.length > 0 ? args[0] : "src/main/resources/truststore");
        Result result = new TslSync(new HttpsFetcher(), Clock.systemUTC(), LOTL_URL, LOTL_SIGNER_SHA256)
                .run(truststore);
        long timestamps = result.anchors().stream().filter(anchor -> "TSA/QTST".equals(anchor.kind())).count();
        System.out.printf("LOTL  %s  seq %d  issued %s  signer %s%n", result.lotl().source(),
                result.lotl().list().sequenceNumber(), result.lotl().list().issueDate(),
                fingerprint(result.lotl().signer()));
        System.out.printf("ES TSL %s  seq %d  issued %s  signer %s%n", result.tsl().source(),
                result.tsl().list().sequenceNumber(), result.tsl().list().issueDate(),
                fingerprint(result.tsl().signer()));
        System.out.printf("Wrote %d anchors (%d CA/QC, %d TSA/QTST) to %s%n", result.anchors().size(),
                result.anchors().size() - timestamps, timestamps, truststore.toAbsolutePath());
    }

    private static String fingerprint(X509Certificate certificate) {
        return Fingerprints.sha256(certificate);
    }
}
