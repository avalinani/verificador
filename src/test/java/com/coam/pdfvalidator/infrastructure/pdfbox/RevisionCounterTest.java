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

    @Test
    void anOutOfRangeStartxrefOffsetFallsBackGracefullyWithoutThrowing() {
        // The declared startxref offset is far beyond the file's actual
        // length: the xref chain walk must never even enter its loop for
        // such a value, falling back to the %%EOF-marker heuristic instead
        // of throwing (e.g. an ArrayIndexOutOfBoundsException).
        byte[] pdf = ("%PDF-1.7\nsome content with no usable xref chain\n"
                + "startxref\n99999999999\n%%EOF\n").getBytes(StandardCharsets.US_ASCII);

        assertThat(RevisionCounter.count(pdf)).isEqualTo(1);
    }

    @Test
    void aCyclicPrevChainTerminatesInsteadOfLoopingForever() {
        byte[] pdf = cyclicPrevDocument();

        assertThat(RevisionCounter.count(pdf))
                .as("the already-visited-offsets guard must stop the walk once a cycle is revisited")
                .isEqualTo(2);
    }

    @Test
    void aLargeHeavilyRevisedFileIsCountedQuickly() {
        int revisionCount = 2000;
        byte[] pdf = manyRevisionsDocument(revisionCount);
        assertThat(pdf.length)
                .as("sanity check: this is genuinely a large (multi-megabyte) synthetic input")
                .isGreaterThan(4_000_000);

        long startNanos = System.nanoTime();
        int counted = RevisionCounter.count(pdf);
        long elapsedMillis = (System.nanoTime() - startNanos) / 1_000_000;

        assertThat(counted).isEqualTo(revisionCount);
        assertThat(elapsedMillis)
                .as("a linear-time xref walk must stay fast even on a large, heavily revised file")
                .isLessThan(3000);
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

    /**
     * Two xref sections whose {@code /Prev} values point at each other,
     * forming a cycle: section A's {@code /Prev} points to section B, and
     * section B's {@code /Prev} points back to section A. The last {@code
     * startxref} (section B's) starts the walk; the second hop back into
     * section A revisits an offset the walk already followed via {@code
     * /Prev}, without ever repeating {@code startxref}'s own offset.
     */
    private static byte[] cyclicPrevDocument() {
        String header = "%PDF-1.7\n";
        int offsetA = header.length();

        String placeholder = "0000000000"; // same fixed width as pad(), patched in once offsetB is known
        String sectionA = "xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R /Prev "
                + placeholder + " >>\nstartxref\n" + pad(offsetA) + "\n%%EOF\n";

        int offsetB = offsetA + sectionA.length();
        String sectionB = "xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R /Prev "
                + pad(offsetA) + " >>\nstartxref\n" + pad(offsetB) + "\n%%EOF\n";

        String sectionAWithCycle = sectionA.replace(placeholder, pad(offsetB));

        return (header + sectionAWithCycle + sectionB).getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * {@code revisionCount} chained xref sections, each padded with filler
     * bytes so the whole file is genuinely large (several megabytes),
     * exercising the linear-time xref walk rather than the previous
     * quadratic one (which rescanned from each hop's offset to the end of
     * the file).
     */
    private static byte[] manyRevisionsDocument(int revisionCount) {
        StringBuilder text = new StringBuilder();
        text.append("%PDF-1.7\n");
        int previousOffset = -1;
        for (int i = 0; i < revisionCount; i++) {
            text.append("% filler ".repeat(250)).append('\n');
            int sectionOffset = text.length();
            text.append("xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R");
            if (previousOffset >= 0) {
                text.append(" /Prev ").append(pad(previousOffset));
            }
            text.append(" >>\nstartxref\n").append(pad(sectionOffset)).append("\n%%EOF\n");
            previousOffset = sectionOffset;
        }
        return text.toString().getBytes(StandardCharsets.US_ASCII);
    }
}
