package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * A real PDF can carry a {@code /Rotate} value that is not a multiple of 90
 * (a hostile or malformed document). {@link PageInfo} must be able to report
 * that anomaly without ever aborting the analysis.
 */
class PageInfoTest {

    private static final Box BOX = new Box(0, 0, 100, 200);

    @Test
    void rotationIsValidForACanonicalMultipleOfNinety() {
        PageInfo page = new PageInfo(1, 90, Rotation.DEG_90, BOX, BOX, Orientation.PORTRAIT);

        assertThat(page.rotationValid()).isTrue();
    }

    @Test
    void rotationIsValidForANonCanonicalButStillAMultipleOfNinety() {
        PageInfo page = new PageInfo(1, 450, Rotation.DEG_90, BOX, BOX, Orientation.PORTRAIT);

        assertThat(page.rotationValid()).isTrue();
    }

    @Test
    void rotationIsInvalidWhenTheRawValueIsNotAMultipleOfNinety() {
        PageInfo page = new PageInfo(1, 45, Rotation.DEG_0, BOX, BOX, Orientation.PORTRAIT);

        assertThat(page.rotationValid()).isFalse();
    }

    @Test
    void rejectsAPageNumberLessThanOne() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new PageInfo(0, 0, Rotation.DEG_0, BOX, BOX, Orientation.PORTRAIT));
    }
}
