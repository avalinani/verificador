package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

class DocumentStructureTest {

    private static final Box BOX = new Box(0, 0, 100, 100);

    @Test
    void acceptsAPageCountMatchingThePagesList() {
        PageInfo page = new PageInfo(1, 0, true, Rotation.DEG_0, BOX, BOX, Orientation.SQUARE);

        assertThatNoException()
                .isThrownBy(() -> new DocumentStructure("1.7", null, 1, List.of(page), 1));
    }

    @Test
    void rejectsAPageCountThatDoesNotMatchThePagesListSize() {
        PageInfo page = new PageInfo(1, 0, true, Rotation.DEG_0, BOX, BOX, Orientation.SQUARE);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DocumentStructure("1.7", null, 2, List.of(page), 1));
    }

    @Test
    void acceptsANullHeaderVersionWhenTheHeaderCouldNotBeFound() {
        PageInfo page = new PageInfo(1, 0, true, Rotation.DEG_0, BOX, BOX, Orientation.SQUARE);

        assertThatNoException()
                .isThrownBy(() -> new DocumentStructure(null, null, 1, List.of(page), 1));
    }
}
