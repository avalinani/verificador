package com.coam.pdfvalidator.tools.tsl;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Offline checks of the downloader. {@code tsl.digital.gob.es} is served
 * under AC RAIZ FNMT-RCM, which the JDK's {@code cacerts} does not ship, so
 * the TLS trust is the JDK default plus that one pinned root.
 */
class HttpsFetcherTest {

    @Test
    void refusesAnythingButHttps() {
        assertThatThrownBy(() -> new HttpsFetcher().fetch(URI.create("http://ec.europa.eu/tools/lotl/eu-lotl.xml")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("HTTPS");
    }

    @Test
    void trustsTheJdkDefaultRootsPlusThePinnedFnmtRootForTls() throws Exception {
        List<X509Certificate> roots = HttpsFetcher.tlsTrustAnchors();

        assertThat(roots).extracting(Fingerprints::sha256)
                .contains(HttpsFetcher.FNMT_ROOT_SHA256)
                .hasSizeGreaterThan(50);
    }

    @Test
    void theExtraTlsRootIsTheIndependentlyVerifiedFnmtRoot() {
        assertThat(HttpsFetcher.FNMT_ROOT_SHA256)
                .isEqualTo("ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa");
    }
}
