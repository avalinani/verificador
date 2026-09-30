package com.coam.pdfvalidator.infrastructure.pdfbox;

import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import com.coam.pdfvalidator.infrastructure.pdfbox.DecodedSizeGuard.LimitExceededException;
import com.coam.pdfvalidator.infrastructure.pdfbox.DecodedSizeGuard.Limits;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The guard must reject decompression bombs by counting decoded bytes in a
 * bounded, streaming way (never materializing the decoded data), while
 * leaving ordinary documents untouched. Fixtures are scaled-down bombs (a few
 * MB inflated) checked against deliberately small limits.
 */
class DecodedSizeGuardTest {

    private static final int MB = 1024 * 1024;
    private static final Limits ONE_MB_STREAM = new Limits(1L * MB, 64L * MB);

    @Test
    void anOrdinaryDocumentIsWithinTheDefaultLimits() throws Exception {
        try (PDDocument document = Loader.loadPDF(TestPdfFactory.pdfA1bCompliant())) {
            assertThatCode(() -> DecodedSizeGuard.check(document, Limits.DEFAULT)).doesNotThrowAnyException();
        }
    }

    @Test
    void aSingleStreamInflatingPastThePerStreamLimitIsRejected() throws Exception {
        try (PDDocument document = Loader.loadPDF(TestPdfFactory.decompressionBomb(1, 8 * MB))) {
            assertThatThrownBy(() -> DecodedSizeGuard.check(document, ONE_MB_STREAM))
                    .isInstanceOf(LimitExceededException.class);
        }
    }

    @Test
    void manyStreamsEachUnderThePerStreamLimitButOverTheTotalAreRejected() throws Exception {
        Limits limits = new Limits(1L * MB, 3L * MB);
        try (PDDocument document = Loader.loadPDF(TestPdfFactory.decompressionBomb(8, MB / 2))) {
            assertThatThrownBy(() -> DecodedSizeGuard.check(document, limits))
                    .isInstanceOf(LimitExceededException.class);
        }
    }

    @Test
    void aStreamJustUnderThePerStreamLimitIsAccepted() throws Exception {
        try (PDDocument document = Loader.loadPDF(TestPdfFactory.decompressionBomb(1, MB / 2))) {
            assertThatCode(() -> DecodedSizeGuard.check(document, ONE_MB_STREAM)).doesNotThrowAnyException();
        }
    }

    @Test
    void chainedFiltersAreBoundedAtEveryStage() throws Exception {
        try (PDDocument document = Loader.loadPDF(TestPdfFactory.doubleFlateBomb(8 * MB))) {
            assertThatThrownBy(() -> DecodedSizeGuard.check(document, ONE_MB_STREAM))
                    .isInstanceOf(LimitExceededException.class);
        }
    }

    @Test
    void imageStreamsAreExemptFromThePerStreamLimitButNotFromTheTotal() throws Exception {
        byte[] pdf = TestPdfFactory.flateImage(4 * MB);
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThatCode(() -> DecodedSizeGuard.check(document, ONE_MB_STREAM)).doesNotThrowAnyException();
            assertThatThrownBy(() -> DecodedSizeGuard.check(document, new Limits(1L * MB, 2L * MB)))
                    .isInstanceOf(LimitExceededException.class);
        }
    }

    @Test
    void decodingToBytesReturnsTheDecodedContentWhenWithinTheLimit() throws Exception {
        try (PDDocument document = Loader.loadPDF(TestPdfFactory.decompressionBombInMetadata(1000))) {
            var metadata = document.getDocumentCatalog().getMetadata();

            byte[] decoded = DecodedSizeGuard.decode(metadata.getCOSObject(), 1L * MB);

            assertThat(decoded).hasSize(1000);
        }
    }

    @Test
    void decodingToBytesRejectsAStreamOverTheLimit() throws Exception {
        try (PDDocument document = Loader.loadPDF(TestPdfFactory.decompressionBombInMetadata(8 * MB))) {
            var metadata = document.getDocumentCatalog().getMetadata();

            assertThatThrownBy(() -> DecodedSizeGuard.decode(metadata.getCOSObject(), 1L * MB))
                    .isInstanceOf(LimitExceededException.class);
        }
    }
}
