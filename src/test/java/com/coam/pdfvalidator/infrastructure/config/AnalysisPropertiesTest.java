package com.coam.pdfvalidator.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import org.springframework.util.unit.DataSize;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AnalysisPropertiesTest {

    @Test
    void defaultsToOneConcurrentAnalysisForTheSmallVm() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxConcurrent()).isEqualTo(1);
        assertThat(props.acquireTimeout()).isEqualTo(Duration.ofSeconds(5));
    }

    @Test
    void canBeRaisedForLargerVms() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(
                Map.of("pdfvalidator.analysis.max-concurrent", "2")))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxConcurrent()).isEqualTo(2);
    }

    @Test
    void decodedStreamLimitsDefaultToSafeValuesForTheOneGigabyteHeap() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxDecodedStreamSize()).isEqualTo(DataSize.ofMegabytes(32));
        assertThat(props.maxDecodedTotalSize()).isEqualTo(DataSize.ofGigabytes(2));
    }

    @Test
    void decodedStreamLimitsAreConfigurable() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(Map.of(
                "pdfvalidator.analysis.max-decoded-stream-size", "1MB",
                "pdfvalidator.analysis.max-decoded-total-size", "64MB")))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxDecodedStreamSize()).isEqualTo(DataSize.ofMegabytes(1));
        assertThat(props.maxDecodedTotalSize()).isEqualTo(DataSize.ofMegabytes(64));
    }

    @Test
    void resourceCapsDefaultToValuesThatFitTheOneGigabyteHeap() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxPages()).isEqualTo(1000);
        assertThat(props.maxRevisionMarkers()).isEqualTo(1_000_000);
        assertThat(props.maxRevisions()).isEqualTo(10_000);
    }

    @Test
    void resourceCapsAreConfigurable() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(Map.of(
                "pdfvalidator.analysis.max-pages", "10",
                "pdfvalidator.analysis.max-revision-markers", "20",
                "pdfvalidator.analysis.max-revisions", "30")))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxPages()).isEqualTo(10);
        assertThat(props.maxRevisionMarkers()).isEqualTo(20);
        assertThat(props.maxRevisions()).isEqualTo(30);
    }

    @Test
    void signatureCapsDefaultToSafeValues() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxSignatureFields()).isEqualTo(50);
        assertThat(props.maxCertificatesPerSignature()).isEqualTo(50);
        assertThat(props.maxChainLength()).isEqualTo(10);
    }

    @Test
    void signatureCapsAreConfigurable() {
        AnalysisProperties props = new Binder(new MapConfigurationPropertySource(Map.of(
                "pdfvalidator.analysis.max-signature-fields", "4",
                "pdfvalidator.analysis.max-certificates-per-signature", "5",
                "pdfvalidator.analysis.max-chain-length", "6")))
                .bindOrCreate("pdfvalidator.analysis", AnalysisProperties.class);

        assertThat(props.maxSignatureFields()).isEqualTo(4);
        assertThat(props.maxCertificatesPerSignature()).isEqualTo(5);
        assertThat(props.maxChainLength()).isEqualTo(6);
    }
}
