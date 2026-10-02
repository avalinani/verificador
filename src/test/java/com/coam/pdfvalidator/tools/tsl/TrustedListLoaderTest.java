package com.coam.pdfvalidator.tools.tsl;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.CA_QC;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.GRANTED;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.NOW;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.SignOptions;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.SigningKey;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.certificate;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.provider;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.service;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.sha256;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.sign;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.signingKey;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.tamper;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.tsl;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A list is accepted only when its single enveloped XML signature covers the
 * whole document, verifies with a pinned signer certificate that is valid
 * now, and the list itself is not past its NextUpdate.
 */
class TrustedListLoaderTest {

    private static final URI SOURCE = URI.create("https://tsl.example.test/TSL.xml");
    private static final SigningKey SIGNER = signingKey("Test Scheme Operator");
    private static final Set<String> PINS = Set.of(sha256(SIGNER.certificate()));
    private static final String LIST = tsl(42, NOW.plus(Duration.ofDays(90)),
            provider("Test TSP", service("Qualified CA one", CA_QC, GRANTED, List.of(), List.of(),
                    certificate("Qualified CA one"))));

    @Test
    void acceptsAListSignedByAPinnedSigner() throws Exception {
        VerifiedTrustedList verified = TrustedListLoader.load(SOURCE, sign(LIST, SIGNER), PINS, NOW);

        assertThat(verified.source()).isEqualTo(SOURCE);
        assertThat(verified.signer()).isEqualTo(SIGNER.certificate());
        assertThat(verified.list().sequenceNumber()).isEqualTo(42);
        assertThat(verified.list().territory()).isEqualTo("ES");
        assertThat(verified.list().services()).hasSize(1);
    }

    @Test
    void rejectsContentTamperedAfterSigning() {
        byte[] tampered = tamper(sign(LIST, SIGNER), "Qualified CA one</Name>", "Qualified CA 0ne</Name>");

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, tampered, PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void rejectsASignerWhoseCertificateIsNotPinned() {
        SigningKey stranger = signingKey("Someone Else");

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, sign(LIST, stranger), PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("not pinned")
                .hasMessageContaining(sha256(stranger.certificate()));
    }

    @Test
    void rejectsAPinnedSignerWhoseCertificateHasExpired() {
        SigningKey expired = signingKey("Expired Operator", NOW.minus(Duration.ofDays(400)),
                NOW.minus(Duration.ofDays(1)));

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, sign(LIST, expired),
                Set.of(sha256(expired.certificate())), NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("not valid");
    }

    @Test
    void rejectsAListWhoseNextUpdateHasPassed() {
        String stale = tsl(42, NOW.minus(Duration.ofHours(1)), provider("Test TSP"));

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, sign(stale, SIGNER), PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("NextUpdate");
    }

    @Test
    void rejectsADocumentCarryingASecondSignature() {
        byte[] doublySigned = sign(sign(LIST, SIGNER), SIGNER, SignOptions.standard());

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, doublySigned, PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("exactly one");
    }

    @Test
    void rejectsAFirstReferenceThatDoesNotCoverTheWholeDocument() {
        byte[] partial = sign(LIST, SIGNER, new SignOptions("#scheme-info", false));

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, partial, PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("URI=\"\"");
    }

    @Test
    void rejectsAWholeDocumentReferenceWhoseTransformsFilterContentOut() {
        byte[] filtered = sign(LIST, SIGNER, new SignOptions("", true));
        // Without the transform check this tamper would go unnoticed: the XPath filter drops the services.
        byte[] tampered = tamper(filtered, "Qualified CA one</Name>", "Qualified CA 0ne</Name>");

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, tampered, PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("transform");
    }

    @Test
    void rejectsAnUnsignedList() {
        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, LIST.getBytes(StandardCharsets.UTF_8), PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("exactly one");
    }

    @Test
    void rejectsADoctypeEvenInAnOtherwiseValidList() {
        String withDoctype = new String(sign(LIST, SIGNER), StandardCharsets.UTF_8)
                .replaceFirst("<TrustServiceStatusList", "<!DOCTYPE TrustServiceStatusList><TrustServiceStatusList");

        assertThatThrownBy(() -> TrustedListLoader.load(SOURCE, withDoctype.getBytes(StandardCharsets.UTF_8),
                PINS, NOW))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("DOCTYPE");
    }
}
