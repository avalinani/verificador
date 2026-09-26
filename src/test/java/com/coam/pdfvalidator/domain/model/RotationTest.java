package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Optional;

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

    @Test
    void tryFromDegreesReturnsTheSameNormalizedValuesAsTheStrictVariant() {
        assertThat(Rotation.tryFromDegrees(0)).contains(Rotation.DEG_0);
        assertThat(Rotation.tryFromDegrees(90)).contains(Rotation.DEG_90);
        assertThat(Rotation.tryFromDegrees(180)).contains(Rotation.DEG_180);
        assertThat(Rotation.tryFromDegrees(270)).contains(Rotation.DEG_270);
        assertThat(Rotation.tryFromDegrees(-90)).contains(Rotation.DEG_270);
        assertThat(Rotation.tryFromDegrees(450)).contains(Rotation.DEG_90);
    }

    @Test
    void tryFromDegreesReturnsEmptyForAValueThatIsNotAMultipleOfNinety() {
        assertThat(Rotation.tryFromDegrees(45)).isEqualTo(Optional.empty());
    }
}
