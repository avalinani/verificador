package com.coam.pdfvalidator.infrastructure.pdfbox;

import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link RevisionCounter} works directly on raw bytes, so it can be tested
 * with hand-crafted, minimal byte layouts that are not full, PDFBox-loadable
 * PDFs -- which matters specifically for the linearized case: PDFBox itself
 * never writes a linearized file (its {@code save}/{@code saveIncremental}
 * never produce the "fast web view" hint-section layout), so a real
 * linearized fixture cannot be produced through {@link TestPdfFactory}.
 * These hand-built byte layouts are the documented substitute.
 */
class RevisionCounterTest {

    @Test
    void aSingleRevisionDocumentCountsAsOne() throws Exception {
        byte[] pdf = TestPdfFactory.unsigned();

        assertThat(RevisionCounter.count(pdf)).isEqualTo(1);
    }

    @Test
    void twoRevisionsChainedByPrevAreCountedAsTwo() {
        byte[] pdf = twoRevisionDocument();

        assertThat(RevisionCounter.count(pdf)).isEqualTo(2);
    }

    @Test
    void aLinearizedLayoutWithTwoXrefSectionsCountsAsOneLogicalRevision() {
        byte[] pdf = linearizedLikeDocument();

        assertThat(RevisionCounter.count(pdf))
                .as("the hint-section xref for the first page is not a separate revision")
                .isEqualTo(1);
    }

    @Test
    void aDocumentWithNoRecognizableXrefChainFallsBackToAtLeastOne() {
        byte[] pdf = "not a pdf at all".getBytes(StandardCharsets.US_ASCII);

        assertThat(RevisionCounter.count(pdf)).isEqualTo(1);
    }

    /**
     * Two ordinary, non-linearized revisions: a trailer with no {@code
     * /Prev}, followed by a second trailer whose {@code /Prev} points back
     * to the first section's {@code xref} keyword offset.
     */
    private static byte[] twoRevisionDocument() {
        return buildChain(false);
    }

    /** Same shape as {@link #twoRevisionDocument()}, but with a leading {@code /Linearized} hint dictionary. */
    private static byte[] linearizedLikeDocument() {
        return buildChain(true);
    }

    private static byte[] buildChain(boolean linearized) {
        StringBuilder text = new StringBuilder();
        text.append("%PDF-1.7\n");
        if (linearized) {
            text.append("1 0 obj\n<< /Linearized 1 /L 0 /H [0 0] /O 3 /E 0 /N 1 /T 0 >>\nendobj\n");
        }

        int firstXrefOffset = text.length();
        text.append("xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R >>\nstartxref\n");
        text.append(pad(firstXrefOffset));
        text.append("\n%%EOF\n");

        int secondXrefOffset = text.length();
        text.append("xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R /Prev ");
        text.append(pad(firstXrefOffset));
        text.append(" >>\nstartxref\n");
        text.append(pad(secondXrefOffset));
        text.append("\n%%EOF\n");

        return text.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** Fixed-width (10-digit) decimal so inserting it never changes any other already-computed offset. */
    private static String pad(int value) {
        return String.format(Locale.ROOT, "%010d", value);
    }
}
