package com.coam.pdfvalidator.infrastructure.pki;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
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

    @Test
    void everyBundledRootIsCurrentlyValid() throws Exception {
        TrustAnchorProvider provider = TrustAnchorProvider.bundled();
        Instant now = Instant.now();

        for (TrustAnchor anchor : provider.trustAnchors()) {
            X509Certificate certificate = anchor.getTrustedCert();
            assertThat(certificate.getNotBefore().toInstant())
                    .as("notBefore for " + certificate.getSubjectX500Principal())
                    .isBefore(now);
            assertThat(certificate.getNotAfter().toInstant())
                    .as("notAfter for " + certificate.getSubjectX500Principal())
                    .isAfter(now);
        }
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
