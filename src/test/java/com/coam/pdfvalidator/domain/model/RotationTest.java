package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class RotationTest {

    @Test
    void normalizesTheFourCanonicalValues() {
        assertThat(Rotation.fromDegrees(0)).isEqualTo(Rotation.DEG_0);
        assertThat(Rotation.fromDegrees(90)).isEqualTo(Rotation.DEG_90);
        assertThat(Rotation.fromDegrees(180)).isEqualTo(Rotation.DEG_180);
        assertThat(Rotation.fromDegrees(270)).isEqualTo(Rotation.DEG_270);
    }

    @Test
    void normalizesAFullTurnBackToZero() {
        assertThat(Rotation.fromDegrees(360)).isEqualTo(Rotation.DEG_0);
    }

    @Test
    void normalizesANegativeValueByWrappingAround() {
        assertThat(Rotation.fromDegrees(-90)).isEqualTo(Rotation.DEG_270);
    }

    @Test
    void normalizesAValueBeyondAFullTurn() {
        assertThat(Rotation.fromDegrees(450)).isEqualTo(Rotation.DEG_90);
    }

    @Test
    void rejectsAValueThatIsNotAMultipleOfNinety() {
        assertThatIllegalArgumentException().isThrownBy(() -> Rotation.fromDegrees(45));
    }
}
