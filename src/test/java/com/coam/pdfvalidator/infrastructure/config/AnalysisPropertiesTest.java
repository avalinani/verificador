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
}
