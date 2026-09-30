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

    @Test
    void aTruncatedPageListMayBeShorterThanThePageCount() {
        PageInfo page = new PageInfo(1, 0, true, Rotation.DEG_0, BOX, BOX, Orientation.SQUARE);

        DocumentStructure structure = new DocumentStructure("1.7", null, 5000, List.of(page), 1, true, false);

        org.assertj.core.api.Assertions.assertThat(structure.pagesTruncated()).isTrue();
        org.assertj.core.api.Assertions.assertThat(structure.pageCount()).isEqualTo(5000);
    }

    @Test
    void aPageListShorterThanThePageCountMustBeFlaggedAsTruncated() {
        PageInfo page = new PageInfo(1, 0, true, Rotation.DEG_0, BOX, BOX, Orientation.SQUARE);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DocumentStructure("1.7", null, 5000, List.of(page), 1, false, false));
    }

    @Test
    void aTruncatedFlagWithACompletePageListIsRejected() {
        PageInfo page = new PageInfo(1, 0, true, Rotation.DEG_0, BOX, BOX, Orientation.SQUARE);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DocumentStructure("1.7", null, 1, List.of(page), 1, true, false));
    }

    @Test
    void theLegacyConstructorMeansNothingWasTruncated() {
        DocumentStructure structure = new DocumentStructure("1.7", null, 0, List.of(), 1);

        org.assertj.core.api.Assertions.assertThat(structure.pagesTruncated()).isFalse();
        org.assertj.core.api.Assertions.assertThat(structure.revisionCountLowerBound()).isFalse();
    }
}
