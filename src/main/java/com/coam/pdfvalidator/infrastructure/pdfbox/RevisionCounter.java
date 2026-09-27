package com.coam.pdfvalidator.infrastructure.pdfbox;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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

    /** Counts revisions (at least 1) for the given raw PDF bytes. */
    static int count(byte[] pdf) {
        MarkerPositions markers = MarkerPositions.scan(pdf);
        List<Long> chain = xrefChainOffsets(pdf, markers);
        int hops = chain.size();
        if (hops == 0) {
            // No startxref/Prev chain could be found at all -- including an
            // out-of-range or otherwise unusable startxref value, which
            // never enters the loop below: fall back to the previous
            // %%EOF-marker heuristic rather than reporting 0.
            return Math.max(countEofMarkers(pdf), 1);
        }
        if (hops > 1 && isLinearized(pdf)) {
            // The hint-section xref for the first page is not itself a
            // separate revision: it is part of the same logical revision as
            // the main xref section it is chained to.
            hops--;
        }
        return Math.max(hops, 1);
    }

    private static List<Long> xrefChainOffsets(byte[] pdf, MarkerPositions markers) {
        List<Long> offsets = new ArrayList<>();
        Set<Long> visited = new HashSet<>();
        Long offset = lastStartXrefOffset(pdf, markers);
        while (offset != null && offset >= 0 && offset < pdf.length && visited.add(offset)) {
            offsets.add(offset);
            offset = prevOffset(pdf, offset, markers);
        }
        return offsets;
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

    private static boolean isLinearized(byte[] pdf) {
        int window = Math.min(pdf.length, LINEARIZATION_SEARCH_WINDOW);
        return indexOf(pdf, LINEARIZED_MARKER, 0, window) >= 0;
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

    private static int countEofMarkers(byte[] pdf) {
        byte[] eof = "%%EOF".getBytes(StandardCharsets.US_ASCII);
        int count = 0;
        int index = 0;
        while ((index = indexOf(pdf, eof, index, pdf.length)) >= 0) {
            count++;
            index += eof.length;
        }
        return count;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex, int limit) {
        int last = Math.min(limit, haystack.length) - needle.length;
        outer:
        for (int i = Math.max(fromIndex, 0); i <= last; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * Every occurrence of {@link #STREAM_KEYWORD}, {@link #STARTXREF} and
     * {@link #PREV} in the file, each found with one forward scan and kept
     * sorted ascending (which a single forward scan naturally produces), so
     * the backward xref walk can locate its bounding markers with a binary
     * search instead of rescanning the file on every hop.
     */
    private static final class MarkerPositions {
        private final long[] streamOffsets;
        private final long[] startxrefOffsets;
        private final long[] prevOffsets;

        private MarkerPositions(long[] streamOffsets, long[] startxrefOffsets, long[] prevOffsets) {
            this.streamOffsets = streamOffsets;
            this.startxrefOffsets = startxrefOffsets;
            this.prevOffsets = prevOffsets;
        }

        static MarkerPositions scan(byte[] pdf) {
            return new MarkerPositions(
                    allOffsetsOf(pdf, STREAM_KEYWORD),
                    allOffsetsOf(pdf, STARTXREF),
                    allOffsetsOf(pdf, PREV));
        }

        /** The smallest element of {@code sorted} that is {@code >= from}, or {@code -1} if none. */
        long firstAtOrAfter(long[] sorted, long from) {
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

    private static long[] allOffsetsOf(byte[] pdf, byte[] needle) {
        List<Long> offsets = new ArrayList<>();
        int from = 0;
        while (true) {
            int idx = indexOf(pdf, needle, from, pdf.length);
            if (idx < 0) {
                break;
            }
            offsets.add((long) idx);
            from = idx + 1;
        }
        long[] result = new long[offsets.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = offsets.get(i);
        }
        return result;
    }
}
