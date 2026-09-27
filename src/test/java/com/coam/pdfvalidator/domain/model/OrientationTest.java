package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OrientationTest {

    private static final Box PORTRAIT_BOX = new Box(0, 0, 210, 297);
    private static final Box LANDSCAPE_BOX = new Box(0, 0, 297, 210);
    private static final Box SQUARE_BOX = new Box(0, 0, 200, 200);

    @Test
    void tallerThanWideIsPortraitWithNoRotation() {
        assertThat(Orientation.of(PORTRAIT_BOX, Rotation.DEG_0)).isEqualTo(Orientation.PORTRAIT);
    }

    @Test
    void widerThanTallIsLandscapeWithNoRotation() {
        assertThat(Orientation.of(LANDSCAPE_BOX, Rotation.DEG_0)).isEqualTo(Orientation.LANDSCAPE);
    }

    @Test
    void equalSidesIsSquareRegardlessOfRotation() {
        assertThat(Orientation.of(SQUARE_BOX, Rotation.DEG_0)).isEqualTo(Orientation.SQUARE);
        assertThat(Orientation.of(SQUARE_BOX, Rotation.DEG_90)).isEqualTo(Orientation.SQUARE);
    }

    @Test
    void ninetyDegreeRotationSwapsPortraitIntoLandscape() {
        assertThat(Orientation.of(PORTRAIT_BOX, Rotation.DEG_90)).isEqualTo(Orientation.LANDSCAPE);
    }

    @Test
    void twoSeventyDegreeRotationSwapsPortraitIntoLandscape() {
        assertThat(Orientation.of(PORTRAIT_BOX, Rotation.DEG_270)).isEqualTo(Orientation.LANDSCAPE);
    }

    @Test
    void oneEightyDegreeRotationDoesNotSwapDimensions() {
        assertThat(Orientation.of(PORTRAIT_BOX, Rotation.DEG_180)).isEqualTo(Orientation.PORTRAIT);
    }
}
