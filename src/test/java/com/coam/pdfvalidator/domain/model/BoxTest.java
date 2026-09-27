package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class BoxTest {

    @Test
    void computesWidthAndHeightFromCorners() {
        Box box = new Box(10, 20, 110, 320);

        assertThat(box.width()).isEqualTo(100f);
        assertThat(box.height()).isEqualTo(300f);
    }

    @Test
    void rejectsAnUpperRightCornerBeforeTheLowerLeftCorner() {
        assertThatIllegalArgumentException().isThrownBy(() -> new Box(0, 0, -1, 10));
        assertThatIllegalArgumentException().isThrownBy(() -> new Box(0, 0, 10, -1));
    }
}
