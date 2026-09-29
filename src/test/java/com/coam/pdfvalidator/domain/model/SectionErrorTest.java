package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class SectionErrorTest {

    @Test
    void storesSectionAndMessage() {
        SectionError error = new SectionError(AnalysisSection.SIGNATURES, "verifier blew up");

        assertThat(error.section()).isEqualTo(AnalysisSection.SIGNATURES);
        assertThat(error.message()).isEqualTo("verifier blew up");
    }

    @Test
    void rejectsNullSection() {
        assertThatNullPointerException().isThrownBy(() -> new SectionError(null, "message"));
    }

    @Test
    void rejectsNullMessage() {
        assertThatNullPointerException().isThrownBy(() -> new SectionError(AnalysisSection.PDFA, null));
    }
}
