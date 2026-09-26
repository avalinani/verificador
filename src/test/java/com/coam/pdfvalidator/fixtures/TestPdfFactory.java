package com.coam.pdfvalidator.fixtures;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.xmpbox.XMPMetadata;
import org.apache.xmpbox.schema.PDFAIdentificationSchema;
import org.apache.xmpbox.xml.XmpSerializer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Test-only factory for PDF byte arrays exercising the properties later
 * tasks need to analyze: signatures (single, tampered, incrementally
 * modified, double), page geometry (rotation, orientation, crop box),
 * encryption/permissions, and malformed input. Never use in production code.
 *
 * <p>Reuses {@link TestPki} (test CA) and {@link TestPdfSigner} (CMS
 * signing) rather than re-implementing signing logic.
 */
public final class TestPdfFactory {

    private TestPdfFactory() {
    }

    /** A minimal, valid, unsigned, unencrypted one-page PDF. */
    public static byte[] unsigned() throws IOException {
        return TestPdfSigner.createSimplePdf();
    }

    /** A minimal, valid, unsigned PDF with the given number of pages. */
    public static byte[] unsignedMultiPage(int pages) throws IOException {
        try (PDDocument document = new PDDocument()) {
            for (int i = 0; i < pages; i++) {
                PDPage page = new PDPage(PDRectangle.A4);
                document.addPage(page);
                try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                    contentStream.beginText();
                    contentStream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                    contentStream.newLineAtOffset(100, 700);
                    contentStream.showText("Page " + (i + 1));
                    contentStream.endText();
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /** A one-page PDF signed once with a fresh test identity. */
    public static byte[] signed() throws IOException {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        return TestPdfSigner.sign(unsigned, identity);
    }

    /**
     * A one-page PDF signed once, declaring the given {@code /SubFilter}
     * (e.g. an unsupported or unrecognized one). Useful for exercising a
     * {@code SignatureVerifier}'s handling of subfilters it does not
     * support, without needing to actually verify the CMS content (which is
     * unaffected by this declared name).
     */
    public static byte[] signedWithSubFilter(String subFilter) throws IOException {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        return TestPdfSigner.sign(unsigned, identity, subFilter);
    }

    /**
     * A signed PDF whose raw {@code /ByteRange} array text has been
     * byte-patched in place (keeping the file's total length, and every
     * other byte offset, unchanged) so its last number ({@code len2})
     * carries a hostile value: same digit width as the original, but with
     * every digit set to {@code 9}. Since a fresh {@link #signed()} PDF's
     * {@code /ByteRange} already covers up to the exact end of the file,
     * any increase to {@code len2} necessarily pushes the covered range
     * past the end of the file. The CMS signature bytes themselves are
     * untouched; a verifier must reject this purely from the {@code
     * /ByteRange} structure, without attempting to parse the CMS.
     */
    public static byte[] signedWithByteRangeExceedingFileLength() throws IOException {
        return patchLastByteRangeNumber(signed(), digits -> "9".repeat(digits.length()));
    }

    /**
     * Same idea as {@link #signedWithByteRangeExceedingFileLength()}, but
     * makes {@code len2} negative instead (same digit width: the leading
     * digit becomes a {@code -} sign).
     */
    public static byte[] signedWithNegativeByteRangeLength() throws IOException {
        return patchLastByteRangeNumber(signed(),
                digits -> digits.length() < 2 ? digits : "-" + "9".repeat(digits.length() - 1));
    }

    /**
     * Replaces the last numeral token inside the first signature's {@code
     * /ByteRange [a b c d]} array with {@code transform.apply(originalText)},
     * which must return a same-length replacement so no other byte offset
     * in the file shifts.
     */
    private static byte[] patchLastByteRangeNumber(byte[] pdf, java.util.function.UnaryOperator<String> transform) {
        byte[] patched = pdf.clone();
        byte[] byteRangeTag = "/ByteRange".getBytes(StandardCharsets.US_ASCII);
        int byteRangeIdx = indexOf(patched, byteRangeTag, 0);
        if (byteRangeIdx < 0) {
            throw new IllegalStateException("No /ByteRange found in the given PDF");
        }
        int openBracket = indexOf(patched, "[".getBytes(StandardCharsets.US_ASCII), byteRangeIdx);
        int closeBracket = indexOf(patched, "]".getBytes(StandardCharsets.US_ASCII), openBracket);

        int i = closeBracket - 1;
        while (Character.isWhitespace((char) patched[i])) {
            i--;
        }
        int lastDigitIdx = i;
        while (i > openBracket && Character.isDigit((char) patched[i - 1])) {
            i--;
        }
        int tokenStart = i;

        String original = new String(patched, tokenStart, lastDigitIdx - tokenStart + 1, StandardCharsets.US_ASCII);
        String replacement = transform.apply(original);
        if (replacement.length() != original.length()) {
            throw new IllegalStateException(
                    "Replacement must keep the same width: '" + original + "' -> '" + replacement + "'");
        }
        byte[] replacementBytes = replacement.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(replacementBytes, 0, patched, tokenStart, replacementBytes.length);
        return patched;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
        int limit = haystack.length - needle.length;
        outer:
        for (int i = fromIndex; i <= limit; i++) {
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
     * A signed PDF that was later loaded and incrementally modified
     * (document info changed, saved incrementally): the original signed
     * bytes are untouched, but the file is now longer than the signed
     * ByteRange.
     */
    public static byte[] signedThenIncrementallyModified() throws IOException {
        return TestPdfSigner.applyIncrementalUpdate(signed());
    }

    /** A signed PDF with a single byte flipped inside the first signed ByteRange. */
    public static byte[] signedThenTampered() throws IOException {
        byte[] signed = signed();
        int[] byteRange = firstByteRange(signed);
        byte[] tampered = signed.clone();
        int tamperOffset = byteRange[0] + 10;
        tampered[tamperOffset] = (byte) (tampered[tamperOffset] ^ 0xFF);
        return tampered;
    }

    /**
     * A PDF signed twice with two independent test identities: the first
     * signature via {@link TestPdfSigner#sign(byte[], TestPki.IssuedIdentity)}
     * on the unsigned document, the second by re-signing the already-signed
     * bytes (also via an incremental save), so each signature covers its own
     * ByteRange.
     */
    public static byte[] doublySigned() throws IOException {
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        byte[] firstSigned = TestPdfSigner.sign(unsigned, TestPki.issueSigningIdentity());
        return TestPdfSigner.sign(firstSigned, TestPki.issueSigningIdentity());
    }

    /**
     * A multi-page PDF where each page's raw COS {@code /Rotate} entry is set
     * to the corresponding value in {@code rotationsPerPage}, via
     * {@code page.getCOSObject().setInt(...)}. This is equivalent to
     * {@link PDPage#setRotation(int)} for this purpose: both simply write the
     * raw integer with no normalization at write time (verified against the
     * PDFBox 3.0.8 bytecode). Normalization and page-tree inheritance only
     * happen when {@link PDPage#getRotation()} reads the value back, so
     * non-normalized raw values (negative, or not a multiple of 90) survive
     * on disk either way and are available for later normalization tests via
     * the raw COS dictionary.
     */
    public static byte[] rotated(int... rotationsPerPage) throws IOException {
        try (PDDocument document = new PDDocument()) {
            for (int rotation : rotationsPerPage) {
                PDPage page = new PDPage(PDRectangle.A4);
                document.addPage(page);
                page.getCOSObject().setInt(COSName.ROTATE, rotation);
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /**
     * A one-page PDF whose raw {@code /Rotate} entry is a non-integral
     * {@code COSFloat} (e.g. {@code 90.5}): a value that, if merely
     * truncated to an {@code int}, could misleadingly look like a valid
     * multiple of 90 (e.g. {@code 90.9} truncates to {@code 90}).
     */
    public static byte[] rotatedWithNonIntegerValue(float rotation) throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            page.getCOSObject().setItem(COSName.ROTATE, new org.apache.pdfbox.cos.COSFloat(rotation));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /** A one-page PDF whose raw {@code /Rotate} entry is not a number at all (a PDF name). */
    public static byte[] rotatedWithNonNumericValue() throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            page.getCOSObject().setItem(COSName.ROTATE, COSName.getPDFName("NotANumber"));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /**
     * A one-page PDF where {@code /Rotate} is set on the shared {@code
     * /Pages} node instead of on the page itself, so the page inherits it per
     * the PDF page-tree inheritance rules ({@link PDPageTree#getInheritableAttribute}).
     */
    public static byte[] rotatedViaInheritedPagesNode(int rotation) throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            document.getPages().getCOSObject().setInt(COSName.ROTATE, rotation);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /** A one-page PDF whose media box is wider than it is tall. */
    public static byte[] landscape() throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDRectangle box = new PDRectangle();
            box.setLowerLeftX(0);
            box.setLowerLeftY(0);
            box.setUpperRightX(842);
            box.setUpperRightY(595);
            PDPage page = new PDPage(box);
            document.addPage(page);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /** A one-page PDF whose crop box is smaller than its media box. */
    public static byte[] withCropBox() throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            PDRectangle cropBox = new PDRectangle();
            cropBox.setLowerLeftX(50);
            cropBox.setLowerLeftY(50);
            cropBox.setUpperRightX(PDRectangle.A4.getWidth() - 50);
            cropBox.setUpperRightY(PDRectangle.A4.getHeight() - 50);
            page.setCropBox(cropBox);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /**
     * An AES-256-encrypted one-page PDF with distinct owner/user passwords
     * and restricted permissions (no printing, no content extraction).
     */
    public static byte[] encrypted(String ownerPassword, String userPassword) throws IOException {
        try (PDDocument document = Loader.loadPDF(TestPdfSigner.createSimplePdf())) {
            AccessPermission permissions = new AccessPermission();
            permissions.setCanPrint(false);
            permissions.setCanExtractContent(false);

            StandardProtectionPolicy policy =
                    new StandardProtectionPolicy(ownerPassword, userPassword, permissions);
            policy.setEncryptionKeyLength(256);
            policy.setPreferAES(true);
            document.protect(policy);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /**
     * An encrypted PDF with an empty user password (opens without prompting)
     * but the same restricted permissions as {@link #encrypted}.
     */
    public static byte[] encryptedWithEmptyUserPassword() throws IOException {
        return encrypted("owner-only-secret", "");
    }

    /** Truncated/garbage bytes that still start with the {@code %PDF-} header. */
    public static byte[] corrupt() throws IOException {
        byte[] valid = TestPdfSigner.createSimplePdf();
        int truncatedLength = Math.min(valid.length, 40);
        byte[] truncated = new byte[truncatedLength];
        System.arraycopy(valid, 0, truncated, 0, truncatedLength);
        return truncated;
    }

    /** Bytes that are not a PDF at all (no {@code %PDF-} header). */
    public static byte[] notAPdf() {
        return "This is definitely not a PDF file.".getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * A one-page PDF carrying XMP metadata with the {@code pdfaid} schema
     * declaring the given PDF/A part and conformance level (e.g. {@code (1,
     * "B")} for PDF/A-1b).
     */
    public static byte[] pdfaDeclared(int part, String conformance) throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);

            XMPMetadata xmp = XMPMetadata.createXMPMetadata();
            PDFAIdentificationSchema pdfaSchema = xmp.createAndAddPDFAIdentificationSchema();
            pdfaSchema.setPart(part);
            try {
                pdfaSchema.setConformance(conformance);
            } catch (org.apache.xmpbox.type.BadFieldValueException e) {
                throw new IOException("Invalid PDF/A conformance level: " + conformance, e);
            }

            ByteArrayOutputStream xmpBytes = new ByteArrayOutputStream();
            try {
                new XmpSerializer().serialize(xmp, xmpBytes, true);
            } catch (javax.xml.transform.TransformerException e) {
                throw new IOException("Failed to serialize XMP metadata", e);
            }

            PDMetadata metadata = new PDMetadata(document);
            metadata.importXMPMetadata(xmpBytes.toByteArray());
            document.getDocumentCatalog().setMetadata(metadata);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /**
     * A valid, PDFBox-loadable PDF whose first bytes do not contain a
     * {@code %PDF-x.y} header: the header bytes are overwritten in place
     * with a same-length, non-matching prefix, so the total file length
     * (and therefore every byte offset the xref table/trailer reference)
     * stays unchanged. PDFBox is lenient about a missing header (it logs a
     * warning and falls back to the catalog's declared version) rather than
     * refusing to load the file, which is the behavior this fixture exists
     * to exercise.
     */
    public static byte[] missingHeader() throws IOException {
        byte[] pdf = unsigned();
        byte[] patched = pdf.clone();
        byte[] replacement = "NOTAPDF!".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(replacement, 0, patched, 0, replacement.length);
        return patched;
    }

    /**
     * A PDF whose XMP metadata stream contains bytes that are not
     * well-formed XML, so parsing it as XMP fails. Exercises the reader's
     * fallback to {@code PdfaDeclaration.NONE} for malformed (as opposed to
     * merely absent) metadata.
     */
    public static byte[] malformedXmpMetadata() throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);

            PDMetadata metadata = new PDMetadata(document);
            metadata.importXMPMetadata("this is not well-formed XML <<<".getBytes(StandardCharsets.UTF_8));
            document.getDocumentCatalog().setMetadata(metadata);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    private static int[] firstByteRange(byte[] pdf) throws IOException {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            return document.getSignatureDictionaries().get(0).getByteRange();
        }
    }
}
