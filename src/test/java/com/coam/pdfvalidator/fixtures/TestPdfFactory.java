package com.coam.pdfvalidator.fixtures;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

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
     * to the corresponding value in {@code rotationsPerPage}, set directly on
     * the page's COS dictionary (not via {@link PDPage#setRotation(int)}) so
     * non-normalized values (negative, or not a multiple of 90) are preserved
     * for later normalization tests.
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

    private static int[] firstByteRange(byte[] pdf) throws IOException {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            return document.getSignatureDictionaries().get(0).getByteRange();
        }
    }
}
