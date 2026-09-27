package com.coam.pdfvalidator.infrastructure.pdfbox;

import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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
    void aLargeHeavilyRevisedFileIsCountedCorrectly() {
        int revisionCount = 2000;
        byte[] pdf = manyRevisionsDocument(revisionCount);
        assertThat(pdf.length)
                .as("sanity check: this is genuinely a large (multi-megabyte) synthetic input")
                .isGreaterThan(4_000_000);

        assertThat(RevisionCounter.count(pdf)).isEqualTo(revisionCount);
    }

    /**
     * Deterministic replacement for a wall-clock performance assertion
     * (flaky on a loaded/slow CI machine): {@link RevisionCounter} exposes a
     * package-private {@link RevisionCounter#countScanSteps(byte[])} that
     * returns, for that single call only, how many byte positions the
     * internal {@code indexOf} inspected -- computed from a local counter
     * instance, never a shared/static field (see {@link
     * #concurrentInvocationsOnDifferentDocumentsProduceCorrectCountsForEach()}
     * for why that matters). The previous, quadratic implementation
     * rescanned from each hop's offset to the end of the file, so its total
     * scan work grew with {@code hops * fileSize} -- roughly the square of
     * the input size for these synthetic documents, since {@code fileSize}
     * itself scales with {@code hops}. A 4x growth in revision count (and
     * thus file size) would have meant roughly a 16x growth in scan work
     * under that implementation. The current linear/{@code O(n log n)}
     * implementation scans each keyword once per call regardless of hop
     * count, so scan work should grow close to 4x, not 16x; a generous
     * margin absorbs the {@code log n} factor from the binary searches and
     * general noise.
     */
    @Test
    void scanWorkGrowsLinearlyNotQuadraticallyWithInputSize() {
        int smallRevisionCount = 500;
        int largeRevisionCount = 2000; // 4x the small case

        long smallSteps = RevisionCounter.countScanSteps(manyRevisionsDocument(smallRevisionCount));
        long largeSteps = RevisionCounter.countScanSteps(manyRevisionsDocument(largeRevisionCount));

        assertThat(smallSteps).isPositive();
        assertThat(largeSteps)
                .as("a 4x larger input must not cost ~16x the scan work of a quadratic implementation")
                .isLessThan(smallSteps * 8);
    }

    /**
     * T06b follow-up: the previous implementation kept its scan-step
     * diagnostic in a {@code static} field reset at the start of every
     * {@link RevisionCounter#count(byte[])} call -- a race condition once
     * the service handles concurrent requests (one thread's reset/read could
     * interleave with another thread's count entirely). Counting itself
     * never used that field's value, so the bug was invisible to every
     * single-threaded test above; this drives many different documents
     * (different, independently-verifiable revision counts) through {@code
     * count} concurrently and asserts every result is exactly the count that
     * document alone would produce, proving the counting itself has no
     * shared mutable state left to race on.
     */
    @Test
    void concurrentInvocationsOnDifferentDocumentsProduceCorrectCountsForEach() throws Exception {
        int threads = 16;
        int callsPerThread = 50;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            List<Callable<Void>> tasks = new java.util.ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int revisionCount = 2 + (t % 5); // varies 2..6 per thread, deterministic per task
                tasks.add(() -> {
                    byte[] pdf = buildChain(false); // baseline 2-revision document
                    for (int i = 0; i < callsPerThread; i++) {
                        assertThat(RevisionCounter.count(pdf)).isEqualTo(2);
                        byte[] many = manyRevisionsDocument(revisionCount);
                        assertThat(RevisionCounter.count(many)).isEqualTo(revisionCount);
                    }
                    return null;
                });
            }
            // T08b: bound invokeAll itself (see the other concurrency test's
            // comment below for why an unbounded invokeAll followed by a
            // per-future timeout never actually bounds anything).
            List<Future<Void>> futures = executor.invokeAll(tasks, 90, TimeUnit.SECONDS);
            for (Future<Void> future : futures) {
                assertThat(future.isCancelled()).as("task must complete within the bounded timeout").isFalse();
                future.get();
            }
        } finally {
            executor.shutdown();
        }
    }

    /**
     * T07b follow-up: {@link
     * #concurrentInvocationsOnDifferentDocumentsProduceCorrectCountsForEach()}
     * asserts on {@link RevisionCounter#count(byte[])}'s return value, which
     * never actually depended on the step-counting field's value in the
     * first place -- a reintroduced {@code static} scan-step counter would
     * still let that test pass, because the revision count itself is
     * computed independently of
     * how many scan steps were taken. This test instead exercises {@link
     * RevisionCounter#countScanSteps(byte[])} itself: it precomputes each
     * document's step count serially (a deterministic baseline), then drives
     * many threads concurrently calling {@code countScanSteps} on several
     * distinctly-sized documents at once and asserts every single call still
     * returns exactly its own document's baseline. A reintroduced shared
     * {@code static} counter would very likely fail this: concurrent calls on
     * different documents would reset/increment the same field mid-scan,
     * polluting each other's counts into values that no longer match the
     * precomputed serial baseline.
     */
    @Test
    void concurrentScanStepCountsMatchEachDocumentsOwnSerialBaselineUnderConcurrency() throws Exception {
        int distinctDocuments = 5;
        int threadsPerDocument = 4;
        int callsPerThread = 100;

        byte[][] documents = new byte[distinctDocuments][];
        long[] baselineSteps = new long[distinctDocuments];
        for (int d = 0; d < distinctDocuments; d++) {
            documents[d] = manyRevisionsDocument(50 + d * 37); // distinct sizes: cross-talk would change the count
            baselineSteps[d] = RevisionCounter.countScanSteps(documents[d]);
        }

        ExecutorService executor = Executors.newFixedThreadPool(distinctDocuments * threadsPerDocument);
        try {
            List<Callable<Void>> tasks = new java.util.ArrayList<>();
            for (int d = 0; d < distinctDocuments; d++) {
                int docIndex = d;
                for (int t = 0; t < threadsPerDocument; t++) {
                    tasks.add(() -> {
                        for (int i = 0; i < callsPerThread; i++) {
                            long steps = RevisionCounter.countScanSteps(documents[docIndex]);
                            assertThat(steps)
                                    .as("scan-step count for document " + docIndex + " must not be polluted by a "
                                            + "concurrently-running call scanning a different document")
                                    .isEqualTo(baselineSteps[docIndex]);
                        }
                        return null;
                    });
                }
            }
            // T08b: executor.invokeAll(tasks) with no timeout blocks until every
            // task finishes, however long that takes -- a per-future
            // future.get(90, SECONDS) afterwards is unreachable-in-practice as a
            // bound, since by the time the loop runs every future is already
            // done. Bounding invokeAll itself makes the timeout actually take
            // effect: a hung task is cancelled and this test fails instead of
            // hanging (verified with a temporary artificial hang while writing
            // this fix -- see the T08b evidence in odd/tasks/pdf-validator.md).
            List<Future<Void>> futures = executor.invokeAll(tasks, 90, TimeUnit.SECONDS);
            for (Future<Void> future : futures) {
                assertThat(future.isCancelled()).as("task must complete within the bounded timeout").isFalse();
                future.get();
            }
        } finally {
            executor.shutdown();
        }
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
