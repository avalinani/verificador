package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class ByteRangeCoverageTest {

    @Test
    void ofBuildsTheFourValueRangeFromTheStaticFactory() {
        ByteRangeCoverage coverage = ByteRangeCoverage.of(0, 100, 150, 50, 200);

        assertThat(coverage.signedRevisionEnd()).isEqualTo(200);
        assertThat(coverage.coversWholeDocument()).isTrue();
    }

    @Test
    void doesNotCoverTheWholeDocumentWhenBytesWereAppendedAfterSigning() {
        ByteRangeCoverage coverage = ByteRangeCoverage.of(0, 100, 150, 50, 400);

        assertThat(coverage.signedRevisionEnd()).isEqualTo(200);
        assertThat(coverage.coversWholeDocument()).isFalse();
    }

    @Test
    void rejectsARangeThatDoesNotStartAtZero() {
        assertThatIllegalArgumentException().isThrownBy(() -> ByteRangeCoverage.of(1, 100, 150, 50, 200));
    }

    @Test
    void rejectsOverlappingRanges() {
        assertThatIllegalArgumentException().isThrownBy(() -> ByteRangeCoverage.of(0, 100, 50, 50, 200));
    }

    @Test
    void rejectsARangeExceedingTheFileLength() {
        assertThatIllegalArgumentException().isThrownBy(() -> ByteRangeCoverage.of(0, 100, 150, 100, 200));
    }

    @Test
    void rejectsAListThatIsNotExactlyFourValues() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new ByteRangeCoverage(List.of(0L, 100L, 150L), 200));
    }
}
