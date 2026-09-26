package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

class PdfaDeclarationTest {

    @Test
    void noneIsNotDeclared() {
        assertThat(PdfaDeclaration.NONE.isDeclared()).isFalse();
    }

    @Test
    void acceptsBothPartAndConformancePresent() {
        assertThatNoException().isThrownBy(() -> new PdfaDeclaration(1, "B"));
    }

    @Test
    void rejectsAPartWithoutAConformance() {
        assertThatIllegalArgumentException().isThrownBy(() -> new PdfaDeclaration(1, null));
    }

    @Test
    void rejectsAConformanceWithoutAPart() {
        assertThatIllegalArgumentException().isThrownBy(() -> new PdfaDeclaration(null, "B"));
    }
}
