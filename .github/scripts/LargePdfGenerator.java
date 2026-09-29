import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Writes a valid, dependency-free multi-page PDF of roughly the requested size,
 * used by the CI "docker" job to load-test the 2 GB container (T12c).
 *
 * <p>Run with the JDK's source launcher, no build needed:
 * {@code java .github/scripts/LargePdfGenerator.java /tmp/large.pdf 19}
 *
 * <p>The size comes from many pages, each with an uncompressed text content
 * stream (rather than one giant stream), so PDFBox and preflight have a real
 * object graph to parse, closer to a scanned/long document than a single blob.
 */
public final class LargePdfGenerator {

    private static final int PAGE_STREAM_BYTES = 100 * 1024;

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("usage: LargePdfGenerator <output.pdf> <size-in-MB>");
            System.exit(2);
        }
        Path out = Path.of(args[0]);
        long targetBytes = Long.parseLong(args[1]) * 1024 * 1024;
        int pages = (int) Math.max(1, targetBytes / PAGE_STREAM_BYTES);

        // Object numbering: 1 = catalog, 2 = pages, 3 = font,
        // then per page i: page = 4 + 2*i, content = 5 + 2*i.
        List<Long> offsets = new ArrayList<>();
        try (CountingStream os = new CountingStream(new BufferedOutputStream(Files.newOutputStream(out), 1 << 16))) {
            write(os, "%PDF-1.7\n%âãÏÓ\n");
            offsets.add(os.count());
            write(os, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

            StringBuilder kids = new StringBuilder();
            for (int i = 0; i < pages; i++) {
                kids.append(4 + 2 * i).append(" 0 R ");
            }
            offsets.add(os.count());
            write(os, "2 0 obj\n<< /Type /Pages /Count " + pages + " /Kids [" + kids + "] >>\nendobj\n");
            offsets.add(os.count());
            write(os, "3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

            byte[] content = pageContent();
            for (int i = 0; i < pages; i++) {
                offsets.add(os.count());
                write(os, (4 + 2 * i) + " 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                        + "/Resources << /Font << /F1 3 0 R >> >> /Contents " + (5 + 2 * i) + " 0 R >>\nendobj\n");
                offsets.add(os.count());
                write(os, (5 + 2 * i) + " 0 obj\n<< /Length " + content.length + " >>\nstream\n");
                os.write(content);
                write(os, "\nendstream\nendobj\n");
            }

            long xrefOffset = os.count();
            int size = offsets.size() + 1;
            StringBuilder xref = new StringBuilder("xref\n0 " + size + "\n0000000000 65535 f \n");
            for (long offset : offsets) {
                xref.append(String.format("%010d 00000 n \n", offset));
            }
            write(os, xref.toString());
            write(os, "trailer\n<< /Size " + size + " /Root 1 0 R >>\nstartxref\n" + xrefOffset + "\n%%EOF\n");
        }
        System.out.println("Wrote " + out + " (" + Files.size(out) + " bytes, " + pages + " pages)");
    }

    /** ~100 KB of distinct-looking text drawing operators. */
    private static byte[] pageContent() {
        StringBuilder sb = new StringBuilder(PAGE_STREAM_BYTES + 128);
        int line = 0;
        while (sb.length() < PAGE_STREAM_BYTES) {
            sb.append("BT /F1 8 Tf 20 ").append(800 - (line % 78) * 10).append(" Td (Line ")
                    .append(line).append(" of synthetic load-test content for the PDF validator) Tj ET\n");
            line++;
        }
        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static void write(OutputStream os, String s) throws IOException {
        os.write(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    /** Tracks the number of bytes written, to compute xref offsets. */
    private static final class CountingStream extends OutputStream {
        private final OutputStream delegate;
        private long count;

        CountingStream(OutputStream delegate) {
            this.delegate = delegate;
        }

        long count() {
            return count;
        }

        @Override
        public void write(int b) throws IOException {
            delegate.write(b);
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            delegate.write(b, off, len);
            count += len;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
