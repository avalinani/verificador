package com.coam.pdfvalidator.infrastructure.pdfbox;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObjectKey;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.filter.DecodeOptions;
import org.apache.pdfbox.filter.Filter;
import org.apache.pdfbox.filter.FilterFactory;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Defence against decompression bombs (T18a). PDFBox decodes a stream fully
 * into memory as soon as anything reads it, and its stream cache does not
 * apply to decoding: a 510 KB {@code /FlateDecode} stream inflating to 500 MB
 * made the PDF/A preflight run out of heap (and, with
 * {@code -XX:+ExitOnOutOfMemoryError}, killed the JVM). This guard decodes
 * every stream once, up front, through a <em>bounded, streaming</em> decode
 * that counts bytes and discards them, and refuses the document as soon as a
 * limit is crossed -- so the heavy consumers (preflight, XMP parsing) only
 * ever see streams whose decoded size is known to be safe.
 *
 * <p>Only the lossless "expansion" filters (Flate, LZW, ASCII85, ASCIIHex,
 * RunLength) are decoded here. Image codecs (DCT, JPX, CCITT, JBIG2) are not
 * applied: the consumers this guards do not materialize them. In a filter
 * chain, intermediate stages are held in a buffer capped at the per-stream
 * limit and the last stage is only counted.
 *
 * <p>Limits: {@link Limits#maxStreamBytes()} applies to every stream except
 * {@code /Subtype /Image} ones (large scanned images are legitimate and are
 * never turned into a single in-memory token); {@link Limits#maxTotalBytes()}
 * applies to all streams together and bounds the CPU spent inflating.
 *
 * <p>Lives in {@code infrastructure.pdfbox} and is shared by the PDF reader
 * and the preflight adapter: it is a PDFBox-level concern, not a port.
 */
public final class DecodedSizeGuard {

    private static final Set<COSName> EXPANDING_FILTERS = Set.of(
            COSName.FLATE_DECODE, COSName.FLATE_DECODE_ABBREVIATION,
            COSName.LZW_DECODE, COSName.LZW_DECODE_ABBREVIATION,
            COSName.ASCII85_DECODE, COSName.ASCII85_DECODE_ABBREVIATION,
            COSName.ASCII_HEX_DECODE, COSName.ASCII_HEX_DECODE_ABBREVIATION,
            COSName.RUN_LENGTH_DECODE, COSName.RUN_LENGTH_DECODE_ABBREVIATION);

    private DecodedSizeGuard() {
    }

    /**
     * @param maxStreamBytes maximum decoded size of one non-image stream
     * @param maxTotalBytes  maximum decoded size of all streams of a document together
     */
    public record Limits(long maxStreamBytes, long maxTotalBytes) {

        /** Sized for the 1 GB production heap with two concurrent analyses. */
        public static final Limits DEFAULT = new Limits(32L * 1024 * 1024, 2L * 1024 * 1024 * 1024);

        public Limits {
            if (maxStreamBytes <= 0 || maxTotalBytes <= 0) {
                throw new IllegalArgumentException("Decoded-size limits must be positive");
            }
        }
    }

    /** Thrown when a stream (or the document as a whole) decodes past a configured limit. */
    public static final class LimitExceededException extends IOException {
        private static final long serialVersionUID = 1L;

        LimitExceededException(String message) {
            super(message);
        }
    }

    /**
     * Decodes (count and discard) every stream of the document and throws
     * {@link LimitExceededException} as soon as a limit is crossed. Streams
     * that cannot be decoded for other reasons (corrupt data, unknown filter)
     * are skipped: reporting those is the consumers' job.
     */
    public static void check(PDDocument document, Limits limits) throws LimitExceededException {
        COSDocument cosDocument = document.getDocument();
        long total = 0;
        for (COSObjectKey key : new ArrayList<>(cosDocument.getXrefTable().keySet())) {
            COSBase object = cosDocument.getObjectFromPool(key).getObject();
            if (!(object instanceof COSStream stream)) {
                continue;
            }
            long remaining = limits.maxTotalBytes() - total;
            boolean image = COSName.IMAGE.equals(stream.getCOSName(COSName.SUBTYPE));
            boolean totalIsTheBound = image || remaining <= limits.maxStreamBytes();
            long cap = totalIsTheBound ? remaining : limits.maxStreamBytes();
            try {
                total += decode(stream, cap, Math.min(cap, limits.maxStreamBytes()), null);
            } catch (LimitExceededException e) {
                throw new LimitExceededException(totalIsTheBound
                        ? "The document exceeds the total decoded size limit of " + limits.maxTotalBytes() + " bytes"
                        : "A stream exceeds the decoded size limit of " + limits.maxStreamBytes() + " bytes");
            } catch (IOException | RuntimeException e) {
                // Corrupt or unsupported stream data: not a size problem.
            }
        }
    }

    /**
     * Fully decodes one stream into memory, refusing it if it would exceed
     * {@code maxBytes}. Every filter of the stream must be a lossless
     * expansion filter; otherwise an {@link IOException} is thrown.
     */
    public static byte[] decode(COSStream stream, long maxBytes) throws IOException {
        List<COSName> filters = filterNames(stream);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (filters.isEmpty()) {
            try (InputStream raw = stream.createRawInputStream()) {
                raw.transferTo(new CappedOutputStream(out, maxBytes));
            }
            return out.toByteArray();
        }
        if (!EXPANDING_FILTERS.containsAll(filters)) {
            throw new IOException("Unsupported filter for bounded decoding: " + filters);
        }
        decode(stream, maxBytes, maxBytes, out);
        return out.toByteArray();
    }

    /**
     * Applies the leading run of expansion filters of {@code stream}; the
     * decoded bytes of the last applied stage are counted (and forwarded to
     * {@code terminal} when non-null). Returns the number of decoded bytes,
     * or 0 when the first filter is not an expansion filter. Intermediate
     * stages of a chain are buffered up to {@code stageCap}, never more.
     */
    private static long decode(COSStream stream, long cap, long stageCap, OutputStream terminal) throws IOException {
        List<COSName> filters = filterNames(stream);
        if (filters.isEmpty() || !EXPANDING_FILTERS.contains(filters.get(0))) {
            return 0;
        }
        InputStream in = stream.createRawInputStream();
        try {
            for (int i = 0; i < filters.size() && EXPANDING_FILTERS.contains(filters.get(i)); i++) {
                boolean last = i == filters.size() - 1 || !EXPANDING_FILTERS.contains(filters.get(i + 1));
                Filter filter = FilterFactory.INSTANCE.getFilter(filters.get(i));
                if (last) {
                    CappedOutputStream counter = new CappedOutputStream(terminal, cap);
                    filter.decode(in, counter, stream, i, DecodeOptions.DEFAULT);
                    return counter.count();
                }
                CappedBuffer stage = new CappedBuffer(stageCap);
                filter.decode(in, stage, stream, i, DecodeOptions.DEFAULT);
                in.close();
                in = stage.asInputStream();
            }
            return 0;
        } finally {
            in.close();
        }
    }

    private static List<COSName> filterNames(COSStream stream) {
        COSBase filters = stream.getFilters();
        List<COSName> names = new ArrayList<>();
        if (filters instanceof COSName name) {
            names.add(name);
        } else if (filters instanceof COSArray array) {
            for (COSBase item : array) {
                if (item instanceof COSName name) {
                    names.add(name);
                }
            }
        }
        return names;
    }

    /** Counts bytes, optionally forwards them, and refuses to go past {@code cap} (sticky). */
    private static final class CappedOutputStream extends OutputStream {
        private final OutputStream target;
        private final long cap;
        private long count;

        CappedOutputStream(OutputStream target, long cap) {
            this.target = target;
            this.cap = cap;
        }

        long count() {
            return count;
        }

        @Override
        public void write(int b) throws IOException {
            reserve(1);
            if (target != null) {
                target.write(b);
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            reserve(len);
            if (target != null) {
                target.write(b, off, len);
            }
        }

        private void reserve(long n) throws LimitExceededException {
            if (count + n > cap) {
                count = cap + 1; // sticky: even if a filter swallows the first failure, later writes fail too
                throw new LimitExceededException("Decoded size limit exceeded");
            }
            count += n;
        }
    }

    /** In-memory intermediate stage of a filter chain, capped at the per-stream limit. */
    private static final class CappedBuffer extends OutputStream {
        private final long cap;
        private byte[] buf = new byte[4096];
        private int count;

        CappedBuffer(long cap) {
            this.cap = cap;
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if ((long) count + len > cap) {
                count = Integer.MAX_VALUE; // sticky
                throw new LimitExceededException("Decoded size limit exceeded");
            }
            if (count + len > buf.length) {
                buf = Arrays.copyOf(buf, (int) Math.min(Math.max((long) buf.length * 2, (long) count + len),
                        Integer.MAX_VALUE - 8));
            }
            System.arraycopy(b, off, buf, count, len);
            count += len;
        }

        InputStream asInputStream() {
            return new ByteArrayInputStream(buf, 0, count);
        }
    }
}
