package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.ByteRangeCoverage;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;

/**
 * Validates a signature's raw {@code /ByteRange} against the actual PDF
 * bytes and, once valid, extracts exactly the bytes that were signed (the
 * two covered ranges concatenated) plus the raw CMS {@code /Contents} bytes.
 *
 * <p>Beyond the shape {@link ByteRangeCoverage} itself enforces (starts at
 * 0, no overlap, within the file), this additionally checks that the gap
 * between the two ranges is exactly the {@code /Contents} hex string
 * including its {@code <} / {@code >} delimiters -- i.e. that {@code
 * /ByteRange} and {@code /Contents} actually agree about where the
 * signature placeholder sits. Any structural problem (including a
 * {@code /ByteRange} the domain itself rejects) surfaces as an {@link
 * IllegalArgumentException}, which the caller maps to {@code
 * INVALID_SIGNATURE} rather than letting it escape.
 *
 * <p><b>Why the expected length must come from {@link PDSignature#getContents()}
 * (no-arg), not {@link PDSignature#getContents(byte[])}</b>: the latter
 * computes the hex string it decodes purely from {@code /ByteRange}'s own
 * numbers ({@code byteRange[0]+byteRange[1]+1} to {@code byteRange[2]-1}),
 * i.e. from the very same gap this class is trying to validate -- deriving
 * the "expected" length from the gap and then comparing it against itself
 * is a tautology that can never fail. {@code getContents()} instead reads
 * the {@code /Contents} entry as PDFBox's own object parser already
 * resolved it (a {@code COSString}, located by walking the document's
 * object structure from the xref table, entirely independently of the
 * {@code /ByteRange} array's declared numbers), giving a genuinely
 * independent length to compare the gap against.
 */
final class SignatureByteRange {

    private final ByteRangeCoverage coverage;
    private final byte[] signedBytes;
    private final byte[] cmsDer;

    private SignatureByteRange(ByteRangeCoverage coverage, byte[] signedBytes, byte[] cmsDer) {
        this.coverage = coverage;
        this.signedBytes = signedBytes;
        this.cmsDer = cmsDer;
    }

    ByteRangeCoverage coverage() {
        return coverage;
    }

    /** The two signed ranges concatenated: the bytes the CMS message digest is computed over. */
    byte[] signedBytes() {
        return signedBytes;
    }

    /** The raw CMS DER bytes decoded from the {@code /Contents} hex string. */
    byte[] cmsDer() {
        return cmsDer;
    }

    static SignatureByteRange parse(byte[] pdf, PDSignature signature) throws IOException {
        int[] byteRange = signature.getByteRange();
        if (byteRange == null || byteRange.length != 4) {
            throw new IllegalArgumentException("Signature has no valid /ByteRange array");
        }
        long start1 = byteRange[0];
        long len1 = byteRange[1];
        long start2 = byteRange[2];
        long len2 = byteRange[3];

        // Throws IllegalArgumentException on any structural violation
        // (does not start at 0, overlapping ranges, negative values,
        // arithmetic overflow, or exceeding the file length).
        ByteRangeCoverage coverage = ByteRangeCoverage.of(start1, len1, start2, len2, pdf.length);

        long gapStart = start1 + len1;
        long gapEnd = start2;
        if (gapStart < 0 || gapEnd > pdf.length || gapStart >= gapEnd) {
            throw new IllegalArgumentException("ByteRange gap is out of bounds: [" + gapStart + ", " + gapEnd + ")");
        }
        if (pdf[(int) gapStart] != '<' || pdf[(int) (gapEnd - 1)] != '>') {
            throw new IllegalArgumentException(
                    "ByteRange gap is not delimited by '<' and '>' as /Contents requires");
        }

        // Independently parsed by PDFBox's own object parser -- see the
        // class Javadoc for why this must not be signature.getContents(pdf).
        byte[] cmsDer = signature.getContents();
        long expectedGapLength = 2L + 2L * cmsDer.length;
        long actualGapLength = gapEnd - gapStart;
        if (actualGapLength != expectedGapLength) {
            throw new IllegalArgumentException(
                    "ByteRange gap length (" + actualGapLength + ") does not match the /Contents hex length ("
                            + expectedGapLength + ")");
        }

        byte[] signedBytes = new byte[(int) (len1 + len2)];
        System.arraycopy(pdf, (int) start1, signedBytes, 0, (int) len1);
        System.arraycopy(pdf, (int) start2, signedBytes, (int) len1, (int) len2);

        return new SignatureByteRange(coverage, signedBytes, cmsDer);
    }
}
