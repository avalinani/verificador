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
 * <p><b>Limitation</b>: this is a byte-level heuristic, same in spirit as
 * the {@code %%EOF}-counting it replaces. A hostile document could forge
 * {@code /Prev} tokens to make the walk loop or under/over-count; the
 * visited-offsets guard below prevents an infinite loop, but does not
 * guarantee the count reflects a well-formed xref chain. Only the outermost,
 * standard case (classic xref tables and cross-reference streams, in a
 * single, non-hybrid chain) is specifically handled.
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
        List<Long> chain = xrefChainOffsets(pdf);
        int hops = chain.size();
        if (hops == 0) {
            // No startxref/Prev chain could be found at all (e.g. corrupt or
            // non-standard structure): fall back to the previous %%EOF-marker
            // heuristic rather than reporting 0.
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

    private static List<Long> xrefChainOffsets(byte[] pdf) {
        List<Long> offsets = new ArrayList<>();
        Set<Long> visited = new HashSet<>();
        Long offset = lastStartXrefOffset(pdf);
        while (offset != null && offset >= 0 && offset < pdf.length && visited.add(offset)) {
            offsets.add(offset);
            offset = prevOffset(pdf, offset);
        }
        return offsets;
    }

    private static Long lastStartXrefOffset(byte[] pdf) {
        int idx = lastIndexOf(pdf, STARTXREF);
        if (idx < 0) {
            return null;
        }
        return parseLongAfter(pdf, idx + STARTXREF.length, pdf.length);
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
    private static Long prevOffset(byte[] pdf, long offset) {
        int start = (int) offset;
        if (start < 0 || start >= pdf.length) {
            return null;
        }
        int limit = pdf.length;
        int streamIdx = indexOf(pdf, STREAM_KEYWORD, start, limit);
        if (streamIdx >= 0) {
            limit = streamIdx;
        }
        int startxrefIdx = indexOf(pdf, STARTXREF, start, limit);
        if (startxrefIdx >= 0) {
            limit = startxrefIdx;
        }
        int prevIdx = indexOf(pdf, PREV, start, limit);
        if (prevIdx < 0) {
            return null;
        }
        return parseLongAfter(pdf, prevIdx + PREV.length, limit);
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

    private static int lastIndexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = haystack.length - needle.length; i >= 0; i--) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
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
}
