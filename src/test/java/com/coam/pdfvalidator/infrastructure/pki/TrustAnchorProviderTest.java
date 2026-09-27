package com.coam.pdfvalidator.infrastructure.pki;

import com.coam.pdfvalidator.fixtures.TestPki;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link TrustAnchorProvider#bundled()} loads the classpath {@code
 * truststore/} roots documented in {@code truststore/SOURCES.md}. This
 * asserts against that same file's independently-verified SHA-256
 * fingerprints (not against a network fetch), and that every bundled root is
 * currently valid, so a test failure here is the signal to revisit
 * {@code SOURCES.md} (an expired or fingerprint-mismatched bundled root is a
 * real problem, not a flaky test).
 */
class TrustAnchorProviderTest {

    /** SHA-256 fingerprints from {@code src/main/resources/truststore/SOURCES.md}, verified there against
     * an independent source (Mozilla NSS root-inclusion records / CCADB-linked certificate trackers). */
    private static final Set<String> EXPECTED_SHA256_FINGERPRINTS = Set.of(
            "EBC5570C29018C4D67B1AA127BAF12F703B4611EBC17B7DAB5573894179B93FA",
            "554153B13D2CF9DDB753BFBE1A4E0AE08D0AA4187058FE60A2B862B2E4B87BCB",
            "9A6EC012E1A7DA9DBE34194D478AD7C0DB1822FB071DF12981496ED104384113",
            "57DE0583EFD2B26E0361DA99DA9DF4648DEF7EE8441C3B728AFA9BCDE0F9B26A",
            "2530CC8E98321502BAD96F9B1FBA1B099E2D299E0F4548BB914F363BC0D4531F",
            "C5C380EB9240FB36A16E15F5D6BAD0BF611F6D03F0EF24229919E7D2D8126C11");

    @Test
    void theBundledTrustStoreLoadsExactlyTheDocumentedRoots() throws Exception {
        TrustAnchorProvider provider = TrustAnchorProvider.bundled();

        assertThat(provider.size()).isEqualTo(EXPECTED_SHA256_FINGERPRINTS.size());

        Set<String> actualFingerprints = new java.util.HashSet<>();
        for (TrustAnchor anchor : provider.trustAnchors()) {
            actualFingerprints.add(sha256Fingerprint(anchor.getTrustedCert()));
        }
        assertThat(actualFingerprints).isEqualTo(EXPECTED_SHA256_FINGERPRINTS);
    }

    /**
     * T06b follow-up: asserting against {@code Instant.now()} is a time
     * bomb -- the earliest-expiring bundled root (FNMT-RCM, {@code notAfter}
     * 2030-01-01 per {@code truststore/SOURCES.md}) would start failing this
     * test years before the certificate itself needs replacing, for no
     * reason related to the code under test. A fixed reference date --
     * comfortably inside every bundled root's validity window, and updated
     * only when {@code truststore/SOURCES.md} itself changes -- makes the
     * test deterministic and ties its lifetime to the actual documented
     * validity data instead of the machine's clock.
     */
    private static final Instant REFERENCE_INSTANT =
            ZonedDateTime.of(2026, 9, 27, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();

    @Test
    void everyBundledRootIsValidAtAFixedReferenceDate() throws Exception {
        TrustAnchorProvider provider = TrustAnchorProvider.bundled();

        for (TrustAnchor anchor : provider.trustAnchors()) {
            X509Certificate certificate = anchor.getTrustedCert();
            assertThat(certificate.getNotBefore().toInstant())
                    .as("notBefore for " + certificate.getSubjectX500Principal())
                    .isBefore(REFERENCE_INSTANT);
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
        // Bundled roots (6) + the external root loaded twice (once from its
        // PEM file, once from its DER file -- java.security.cert.TrustAnchor
        // has no value-based equals/hashCode, so these remain two distinct
        // TrustAnchor instances even though they wrap the same certificate)
        // + the garbage file skipped entirely (not counted).
        assertThat(provider.size()).isEqualTo(EXPECTED_SHA256_FINGERPRINTS.size() + 2);
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
        assertThat(provider.size()).isEqualTo(EXPECTED_SHA256_FINGERPRINTS.size() + 1);
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

        assertThat(provider.size()).isEqualTo(EXPECTED_SHA256_FINGERPRINTS.size());
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
            return HexFormat.of().withUpperCase().formatHex(digest.digest(certificate.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
