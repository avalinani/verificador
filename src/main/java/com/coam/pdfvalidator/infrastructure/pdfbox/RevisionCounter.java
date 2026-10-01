package com.coam.pdfvalidator.infrastructure.pdfbox;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Counts a PDF's incremental-update revisions by walking the cross-reference
 * chain, rather than by counting raw {@code %%EOF} byte markers: a
 * linearized PDF (Adobe's "fast web view" layout) writes two independent
 * cross-reference sections linked by {@code /Prev} for what is really a
 * single logical revision, so a naive {@code %%EOF} count over-reports it by
 * one.
 *
 * <p>This walks backwards from the file's last {@code startxref} pointer,
 * following each trailer's (or cross-reference stream's) {@code /Prev} link
 * until none remains, counting one hop per xref section visited. It works
 * directly on the raw bytes -- not through PDFBox's object model -- both
 * because a hostile/corrupt file must never make this throw, and so this
 * helper is unit-testable with hand-crafted byte arrays that do not need to
 * be a fully loadable PDF (PDFBox itself never linearizes on save, so a real
 * linearized fixture cannot be produced through it).
 *
 * <p><b>Linear, not quadratic</b>: every occurrence of the three fixed
 * keywords this class looks for ({@code stream}, {@code startxref}, {@code
 * /Prev}) is found with exactly one forward scan per keyword over the whole
 * file ({@link MarkerPositions#scan}), never rescanned per hop. Each hop of
 * the backward walk then locates its bounding markers with a binary search
 * over those (already sorted) positions, so the total cost is {@code
 * O(n log n)} regardless of how many revisions the chain has, rather than
 * the previous {@code O(hops * n)} (each hop rescanning from its offset to
 * the end of the file).
 *
 * <p>An invalid or out-of-range {@code startxref} value (garbage, negative,
 * or past the end of the file) is handled the same way as finding no xref
 * chain at all: this falls back to the {@code %%EOF}-marker heuristic rather
 * than throwing. The already-visited-offsets guard below additionally
 * bounds the walk against a cyclic {@code /Prev} chain (a hostile file
 * forging two sections whose {@code /Prev} values point at each other):
 * revisiting an offset stops the walk immediately instead of looping.
 *
 * <p><b>Limitation</b>: this is a byte-level heuristic, same in spirit as
 * the {@code %%EOF}-counting it replaces. A hostile document could forge
 * {@code /Prev} tokens to make the walk loop or under/over-count; the
 * visited-offsets guard prevents an infinite loop, but does not guarantee
 * the count reflects a well-formed xref chain. Only the outermost, standard
 * case (classic xref tables and cross-reference streams, in a single,
 * non-hybrid chain) is specifically handled.
 */
final class RevisionCounter {

    private static final byte[] STARTXREF = "startxref".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PREV = "/Prev".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] STREAM_KEYWORD = "stream".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LINEARIZED_MARKER = "/Linearized".getBytes(StandardCharsets.US_ASCII);
    private static final int LINEARIZATION_SEARCH_WINDOW = 2048;

    private RevisionCounter() {
    }

    /**
     * Per-call scan-step accounting: how many byte positions {@link
     * #indexOf}'s outer loop inspected. Previously this was a single
     * {@code static} field reset at the start of {@link #count(byte[])} --
     * harmless for a single-threaded test, but a genuine race condition once
     * the service handles concurrent requests (one thread's reset could wipe
     * out another thread's in-flight count, and one thread's read via the
     * old {@code lastScanStepCount()} could observe a different call's
     * total). Replaced with a local, non-static counter instance created
     * fresh by every {@link #count(byte[])}/{@link #countScanSteps(byte[])}
     * call and threaded through the scan as a plain parameter: no shared
     * mutable state remains, so concurrent calls on different (or the same)
     * input can never interfere with each other.
     */
    private static final class ScanStats {
        private long steps;
    }

    /**
     * Revision count of a file: {@code value} is exact unless {@code lowerBound}, in which case a resource cap
     * ({@link StructureLimits}) stopped the analysis and the file has <em>at least</em> {@code value} revisions.
     */
    record RevisionCount(int value, boolean lowerBound) {
    }

    /** Counts revisions (at least 1) for the given raw PDF bytes, with the default caps. */
    static int count(byte[] pdf) {
        return count(pdf, StructureLimits.DEFAULT).value();
    }

    /** Counts revisions under the given caps; a hostile file can make the result a lower bound, never fail. */
    static RevisionCount count(byte[] pdf, StructureLimits limits) {
        return count(pdf, limits, new ScanStats());
    }

    /**
     * Test-only diagnostic: total byte-position scan steps performed by
     * counting revisions for {@code pdf}, in one call, with no shared state
     * across calls (see {@link ScanStats}). Lets {@code RevisionCounterTest}
     * assert that scan work grows linearly (not quadratically) with input
     * size deterministically, without relying on wall-clock timing, which is
     * flaky on a loaded CI machine.
     */
    static long countScanSteps(byte[] pdf) {
        ScanStats stats = new ScanStats();
        count(pdf, StructureLimits.DEFAULT, stats);
        return stats.steps;
    }

    private static RevisionCount count(byte[] pdf, StructureLimits limits, ScanStats stats) {
        MarkerPositions markers = MarkerPositions.scan(pdf, limits.maxRevisionMarkers(), stats);
        if (markers == null) {
            // T20: more markers than the cap -- not a real revision history. The scan stopped at the cap, so
            // nothing is known beyond the single original revision every file has.
            return new RevisionCount(1, true);
        }
        XrefChain chain = xrefChainOffsets(pdf, markers, limits.maxRevisions());
        int hops = chain.offsets().size();
        if (hops == 0) {
            // No startxref/Prev chain could be found at all -- including an
            // out-of-range or otherwise unusable startxref value, which
            // never enters the loop below: fall back to the previous
            // %%EOF-marker heuristic rather than reporting 0.
            return new RevisionCount(Math.max(countEofMarkers(pdf, stats), 1), false);
        }
        if (chain.truncated()) {
            return new RevisionCount(hops, true);
        }
        if (hops > 1 && isLinearized(pdf, stats)) {
            // The hint-section xref for the first page is not itself a
            // separate revision: it is part of the same logical revision as
            // the main xref section it is chained to.
            hops--;
        }
        return new RevisionCount(Math.max(hops, 1), false);
    }

    private record XrefChain(List<Long> offsets, boolean truncated) {
    }

    private static XrefChain xrefChainOffsets(byte[] pdf, MarkerPositions markers, int maxRevisions) {
        List<Long> offsets = new ArrayList<>();
        Set<Long> visited = new HashSet<>();
        Long offset = lastStartXrefOffset(pdf, markers);
        while (offset != null && offset >= 0 && offset < pdf.length && visited.add(offset)) {
            if (offsets.size() >= maxRevisions) {
                return new XrefChain(offsets, true);
            }
            offsets.add(offset);
            offset = prevOffset(pdf, offset, markers);
        }
        return new XrefChain(offsets, false);
    }

    private static Long lastStartXrefOffset(byte[] pdf, MarkerPositions markers) {
        if (markers.startxrefOffsets.length == 0) {
            return null;
        }
        long lastStartxref = markers.startxrefOffsets[markers.startxrefOffsets.length - 1];
        return parseLongAfter(pdf, (int) lastStartxref + STARTXREF.length, pdf.length);
    }

    /**
     * Looks for a {@code /Prev} key within the xref section starting at
     * {@code offset} (either a classic {@code trailer << ... >>} dictionary,
     * or a cross-reference stream object's dictionary) and returns the
     * offset it points to, or {@code null} if there is none. The search is
     * bounded to stop at the first {@code stream} keyword (cross-reference
     * streams keep their dictionary before the stream data) or the next
     * {@code startxref} keyword (classic trailers end there), so a
     * coincidental {@code /Prev}-like byte sequence elsewhere in the file
     * cannot be picked up.
     */
    private static Long prevOffset(byte[] pdf, long offset, MarkerPositions markers) {
        int start = (int) offset;
        if (start < 0 || start >= pdf.length) {
            return null;
        }
        long limit = pdf.length;

        long streamIdx = markers.firstAtOrAfter(markers.streamOffsets, start);
        if (streamIdx >= 0 && streamIdx + STREAM_KEYWORD.length <= limit) {
            limit = streamIdx;
        }
        long startxrefIdx = markers.firstAtOrAfter(markers.startxrefOffsets, start);
        if (startxrefIdx >= 0 && startxrefIdx + STARTXREF.length <= limit) {
            limit = startxrefIdx;
        }
        long prevIdx = markers.firstAtOrAfter(markers.prevOffsets, start);
        if (prevIdx < 0 || prevIdx + PREV.length > limit) {
            return null;
        }
        return parseLongAfter(pdf, (int) prevIdx + PREV.length, (int) limit);
    }

    private static boolean isLinearized(byte[] pdf, ScanStats stats) {
        int window = Math.min(pdf.length, LINEARIZATION_SEARCH_WINDOW);
        return indexOf(pdf, LINEARIZED_MARKER, 0, window, stats) >= 0;
    }

    private static Long parseLongAfter(byte[] pdf, int from, int limit) {
        int i = from;
        while (i < limit && isWhitespace(pdf[i])) {
            i++;
        }
        int digitsStart = i;
        while (i < limit && pdf[i] >= '0' && pdf[i] <= '9') {
            i++;
        }
        if (i == digitsStart) {
            return null;
        }
        try {
            return Long.parseLong(new String(pdf, digitsStart, i - digitsStart, StandardCharsets.US_ASCII));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static boolean isWhitespace(byte b) {
        return b == ' ' || b == '\r' || b == '\n' || b == '\t' || b == 0;
    }

    private static int countEofMarkers(byte[] pdf, ScanStats stats) {
        byte[] eof = "%%EOF".getBytes(StandardCharsets.US_ASCII);
        int count = 0;
        int index = 0;
        while ((index = indexOf(pdf, eof, index, pdf.length, stats)) >= 0) {
            count++;
            index += eof.length;
        }
        return count;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex, int limit, ScanStats stats) {
        int last = Math.min(limit, haystack.length) - needle.length;
        for (int i = Math.max(fromIndex, 0); i <= last; i++) {
            stats.steps++;
            if (matchesAt(haystack, needle, i)) {
                return i;
            }
        }
        return -1;
    }

    private static boolean matchesAt(byte[] haystack, byte[] needle, int offset) {
        for (int j = 0; j < needle.length; j++) {
            if (haystack[offset + j] != needle[j]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Every occurrence of {@link #STREAM_KEYWORD}, {@link #STARTXREF} and
     * {@link #PREV} in the file, each found with one forward scan and kept
     * sorted ascending (which a single forward scan naturally produces), so
     * the backward xref walk can locate its bounding markers with a binary
     * search instead of rescanning the file on every hop.
     */
    private static final class MarkerPositions {
        private final int[] streamOffsets;
        private final int[] startxrefOffsets;
        private final int[] prevOffsets;

        private MarkerPositions(int[] streamOffsets, int[] startxrefOffsets, int[] prevOffsets) {
            this.streamOffsets = streamOffsets;
            this.startxrefOffsets = startxrefOffsets;
            this.prevOffsets = prevOffsets;
        }

        /** Every marker position, or {@code null} as soon as any keyword occurs more than {@code max} times. */
        static MarkerPositions scan(byte[] pdf, int max, ScanStats stats) {
            Optional<int[]> stream = allOffsetsOf(pdf, STREAM_KEYWORD, max, stats);
            if (stream.isEmpty()) {
                return null;
            }
            Optional<int[]> startxref = allOffsetsOf(pdf, STARTXREF, max, stats);
            if (startxref.isEmpty()) {
                return null;
            }
            Optional<int[]> prev = allOffsetsOf(pdf, PREV, max, stats);
            return prev.isEmpty() ? null : new MarkerPositions(stream.get(), startxref.get(), prev.get());
        }

        /** The smallest element of {@code sorted} that is {@code >= from}, or {@code -1} if none. */
        long firstAtOrAfter(int[] sorted, long from) {
            int lo = 0;
            int hi = sorted.length;
            while (lo < hi) {
                int mid = (lo + hi) >>> 1;
                if (sorted[mid] < from) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return lo < sorted.length ? sorted[lo] : -1;
        }
    }

    /**
     * All occurrences of {@code needle}, in a primitive array grown on demand (an offset is an {@code int}: the
     * upload limit keeps a file well below 2 GB), or empty once there are more than {@code max} of them.
     */
    private static Optional<int[]> allOffsetsOf(byte[] pdf, byte[] needle, int max, ScanStats stats) {
        int[] offsets = new int[16];
        int size = 0;
        int from = 0;
        while (true) {
            int idx = indexOf(pdf, needle, from, pdf.length, stats);
            if (idx < 0) {
                break;
            }
            if (size == max) {
                return Optional.empty();
            }
            if (size == offsets.length) {
                offsets = java.util.Arrays.copyOf(offsets, (int) Math.min(max, 2L * offsets.length));
            }
            offsets[size] = idx;
            size++;
            from = idx + 1;
        }
        return Optional.of(java.util.Arrays.copyOf(offsets, size));
    }
}
