package com.coam.pdfvalidator.infrastructure.pki;

import com.coam.pdfvalidator.fixtures.TestPki;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link TrustAnchorProvider#bundled()} loads exactly the classpath {@code
 * truststore/} anchors listed in {@code truststore/index.txt}. Since T14 that
 * directory is generated from the official EU trusted lists by the
 * maintainer tool {@code com.coam.pdfvalidator.tools.tsl.TslSync}, so these
 * assertions are about consistency (index, files and {@code SOURCES.md}
 * agree) rather than about a hand-maintained list of fingerprints -- plus a
 * canary on the issuing CAs that real Spanish signatures depend on, so a
 * regeneration that drops one of them fails here and gets a human look.
 */
class TrustAnchorProviderTest {

    /** AC FNMT Usuarios: issues most citizen certificates; real FNMT-signed PDFs embed only the signer (T09d). */
    private static final String AC_FNMT_USUARIOS_SHA256 =
            "601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869";
    /** AC RAIZ DNIE 2: the Spanish national ID card (DNIe) CA, published as a CA/QC service in the ES TSL. */
    private static final String AC_RAIZ_DNIE_2_SHA256 =
            "c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11";

    private static List<String> indexedFiles() throws Exception {
        try (InputStream in = TrustAnchorProviderTest.class.getClassLoader()
                .getResourceAsStream(TrustAnchorProvider.BUNDLED_INDEX)) {
            assertThat(in).as("the generated index " + TrustAnchorProvider.BUNDLED_INDEX).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).lines()
                    .map(String::strip)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .toList();
        }
    }

    private static String sources() throws Exception {
        try (InputStream in = TrustAnchorProviderTest.class.getClassLoader()
                .getResourceAsStream("truststore/SOURCES.md")) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).replace(":", "").toLowerCase(Locale.ROOT);
        }
    }

    @Test
    void theBundledTrustStoreLoadsExactlyTheIndexedAnchorsEachDocumentedInSources() throws Exception {
        TrustAnchorProvider provider = TrustAnchorProvider.bundled();
        List<String> files = indexedFiles();

        assertThat(files).isNotEmpty().doesNotHaveDuplicates();
        assertThat(provider.size()).isEqualTo(files.size());
        String sources = sources();
        for (String fingerprint : fingerprintsOf(provider)) {
            assertThat(sources).as("SOURCES.md documents " + fingerprint).contains(fingerprint);
        }
    }

    @Test
    void theBundledTrustStoreCoversTheIssuingCasOfRealSpanishSignatures() throws Exception {
        assertThat(fingerprintsOf(TrustAnchorProvider.bundled()))
                .contains(AC_FNMT_USUARIOS_SHA256, AC_RAIZ_DNIE_2_SHA256);
    }

    /**
     * T06b follow-up: asserting against {@code Instant.now()} for expiry is a
     * time bomb -- the test would start failing before anyone regenerates the
     * store, for no reason related to the code under test. The generator
     * (T14) only bundles certificates whose {@code notAfter} is still in the
     * future when it runs, so every anchor must be unexpired at the fixed
     * date of the first generation; {@code notBefore} can safely be checked
     * against the clock (it only becomes more true over time).
     */
    private static final Instant REFERENCE_INSTANT =
            ZonedDateTime.of(2026, 10, 2, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();

    @Test
    void everyBundledAnchorIsAlreadyValidAndUnexpiredAtAFixedReferenceDate() throws Exception {
        TrustAnchorProvider provider = TrustAnchorProvider.bundled();

        for (TrustAnchor anchor : provider.trustAnchors()) {
            X509Certificate certificate = anchor.getTrustedCert();
            assertThat(certificate.getNotBefore().toInstant())
                    .as("notBefore for " + certificate.getSubjectX500Principal())
                    .isBefore(Instant.now());
            assertThat(certificate.getNotAfter().toInstant())
                    .as("notAfter for " + certificate.getSubjectX500Principal())
                    .isAfter(REFERENCE_INSTANT);
        }
    }

    /**
     * T06b follow-up: {@link TrustAnchorProvider#load} additionally accepts
     * an external directory of certificate files (PEM or DER, one per file);
     * previously untested. A malformed file in that directory must not abort
     * loading the rest of the trust store -- it is skipped (and logged),
     * matching the "a single bad input never aborts the whole analysis"
     * convention used throughout this codebase's other adapters.
     */
    @Test
    void loadsPemAndDerCertificatesFromAnExternalDirectorySkippingInvalidFiles(@TempDir Path directory)
            throws Exception {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        X509Certificate externalRoot = identity.rootCertificate();

        Files.writeString(directory.resolve("root.pem"), toPem(externalRoot), StandardCharsets.US_ASCII);
        Files.write(directory.resolve("root.der"), externalRoot.getEncoded());
        Files.writeString(directory.resolve("not-a-certificate.txt"), "this is not a certificate at all");

        TrustAnchorProvider provider = TrustAnchorProvider.load(directory, null, null);

        Set<String> fingerprints = fingerprintsOf(provider);
        assertThat(fingerprints).contains(sha256Fingerprint(externalRoot));
        // Bundled anchors + the external root loaded twice (once from its
        // PEM file, once from its DER file -- java.security.cert.TrustAnchor
        // has no value-based equals/hashCode, so these remain two distinct
        // TrustAnchor instances even though they wrap the same certificate)
        // + the garbage file skipped entirely (not counted).
        assertThat(provider.size()).isEqualTo(indexedFiles().size() + 2);
    }

    /**
     * T06b follow-up: {@link TrustAnchorProvider#load} also accepts a
     * PKCS#12 keystore file as a trust anchor source; previously untested.
     * Builds a real, throwaway PKCS#12 file in a temp directory (never
     * committed) holding one {@link TestPki} root as a trusted-certificate
     * entry.
     */
    @Test
    void loadsCertificatesFromAPkcs12KeystoreFile(@TempDir Path directory) throws Exception {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        X509Certificate pkcs12Root = identity.rootCertificate();
        char[] password = "test-only-password".toCharArray();

        Path pkcs12File = directory.resolve("trust.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("root", pkcs12Root);
        try (var out = Files.newOutputStream(pkcs12File)) {
            keyStore.store(out, password);
        }

        TrustAnchorProvider provider = TrustAnchorProvider.load(null, pkcs12File, password);

        assertThat(fingerprintsOf(provider)).contains(sha256Fingerprint(pkcs12Root));
        assertThat(provider.size()).isEqualTo(indexedFiles().size() + 1);
    }

    /**
     * T07b follow-up: an external directory that cannot even be listed (here,
     * one that does not exist -- {@code Files.newDirectoryStream} throws
     * {@code NoSuchFileException}, an {@link java.io.IOException}) must not
     * abort loading the trust store either; it is treated as "no
     * certificates from this source" (logged), same as a single unreadable
     * file inside an otherwise-listable directory.
     */
    @Test
    void aNonExistentExternalDirectoryIsSkippedRatherThanThrowing(@TempDir Path parent) throws Exception {
        Path missingDirectory = parent.resolve("does-not-exist");

        TrustAnchorProvider provider = TrustAnchorProvider.load(missingDirectory, null, null);

        assertThat(provider.size()).isEqualTo(indexedFiles().size());
    }

    private static Set<String> fingerprintsOf(TrustAnchorProvider provider) throws NoSuchAlgorithmException {
        Set<String> fingerprints = new java.util.HashSet<>();
        for (TrustAnchor anchor : provider.trustAnchors()) {
            fingerprints.add(sha256Fingerprint(anchor.getTrustedCert()));
        }
        return fingerprints;
    }

    private static String toPem(X509Certificate certificate) throws java.security.cert.CertificateEncodingException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    private static String sha256Fingerprint(X509Certificate certificate) throws NoSuchAlgorithmException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(certificate.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void parseIndexReturnsTheEntriesInOrderSkippingCommentsAndBlankLines() throws Exception {
        String content = "# generated\n\nroot-a.crt\n  \n# note\nroot-b.crt\r\nroot-c.crt\n";

        assertThat(TrustAnchorProvider.parseIndex(content))
                .containsExactly("truststore/root-a.crt", "truststore/root-b.crt", "truststore/root-c.crt");
    }

    @Test
    void parseIndexRejectsAnEmptyIndex() {
        assertThatThrownBy(() -> TrustAnchorProvider.parseIndex(""))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("lists no trust anchors")
                .hasMessageContaining(TrustAnchorProvider.BUNDLED_INDEX);
    }

    @Test
    void parseIndexRejectsAnIndexWithOnlyCommentsAndBlankLines() {
        assertThatThrownBy(() -> TrustAnchorProvider.parseIndex("# generated\n\n   \n# nothing here\n"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("lists no trust anchors");
    }

    @Test
    void parseIndexRejectsAnInvalidEntry() {
        assertThatThrownBy(() -> TrustAnchorProvider.parseIndex("root-a.crt\n../evil.crt\n"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Invalid entry")
                .hasMessageContaining("../evil.crt");
    }
}
