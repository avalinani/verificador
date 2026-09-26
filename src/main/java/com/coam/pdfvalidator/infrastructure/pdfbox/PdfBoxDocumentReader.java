package com.coam.pdfvalidator.infrastructure.pdfbox;

import com.coam.pdfvalidator.domain.exception.EncryptedPdfException;
import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.Box;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.Orientation;
import com.coam.pdfvalidator.domain.model.PageInfo;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.Permission;
import com.coam.pdfvalidator.domain.model.Rotation;
import com.coam.pdfvalidator.domain.model.SecurityInfo;
import com.coam.pdfvalidator.domain.port.PdfDocumentReader;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.xmpbox.XMPMetadata;
import org.apache.xmpbox.schema.PDFAIdentificationSchema;
import org.apache.xmpbox.xml.DomXmpParser;
import org.apache.xmpbox.xml.XmpParsingException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@link PdfDocumentReader} adapter built on Apache PDFBox 3. Never lets a
 * PDFBox type escape into a caller: parsing failures become the domain's own
 * {@link InvalidPdfException} (unreadable/corrupt input) or
 * {@link EncryptedPdfException} (a non-empty user password is required).
 *
 * <p>A plain class, constructor-injectable; Spring wiring is added in a
 * later task.
 */
public class PdfBoxDocumentReader implements PdfDocumentReader {

    private static final Pattern HEADER_VERSION = Pattern.compile("%PDF-(\\d\\.\\d)");
    private static final byte[] EOF_MARKER = "%%EOF".getBytes(StandardCharsets.US_ASCII);
    private static final int HEADER_SEARCH_WINDOW = 1024;

    @Override
    public DocumentStructure readStructure(byte[] pdf) {
        try (PDDocument document = load(pdf)) {
            String headerVersion = parseHeaderVersion(pdf);
            PDDocumentCatalog catalog = document.getDocumentCatalog();
            String catalogVersion = catalog.getVersion();

            List<PageInfo> pages = new ArrayList<>();
            int number = 1;
            for (PDPage page : document.getPages()) {
                pages.add(readPageInfo(number++, page));
            }

            int revisionCount = countRevisions(pdf);
            return new DocumentStructure(headerVersion, catalogVersion, pages.size(), pages, revisionCount);
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to close PDF document after reading its structure", e);
        }
    }

    @Override
    public SecurityInfo readSecurity(byte[] pdf) {
        try (PDDocument document = load(pdf)) {
            if (!document.isEncrypted()) {
                return new SecurityInfo(false, EnumSet.allOf(Permission.class));
            }
            AccessPermission access = document.getCurrentAccessPermission();
            return new SecurityInfo(true, toPermissions(access));
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to close PDF document after reading its security info", e);
        }
    }

    @Override
    public PdfaDeclaration readPdfaDeclaration(byte[] pdf) {
        try (PDDocument document = load(pdf)) {
            PDMetadata metadata = document.getDocumentCatalog().getMetadata();
            if (metadata == null) {
                return PdfaDeclaration.NONE;
            }
            return parsePdfaDeclaration(metadata);
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to close PDF document after reading its PDF/A declaration", e);
        }
    }

    private static PdfaDeclaration parsePdfaDeclaration(PDMetadata metadata) {
        try {
            byte[] xmpBytes = metadata.toByteArray();
            XMPMetadata xmp = new DomXmpParser().parse(xmpBytes);
            PDFAIdentificationSchema schema = xmp.getPDFAIdentificationSchema();
            if (schema == null) {
                return PdfaDeclaration.NONE;
            }
            Integer part = schema.getPart();
            String conformance = schema.getConformance();
            if (part == null || conformance == null) {
                return PdfaDeclaration.NONE;
            }
            return new PdfaDeclaration(part, conformance);
        } catch (IOException | XmpParsingException e) {
            // Malformed or unparseable XMP is not itself the PDF content: treat
            // it as "no PDF/A declaration" rather than aborting the analysis.
            return PdfaDeclaration.NONE;
        }
    }

    private static Set<Permission> toPermissions(AccessPermission access) {
        Set<Permission> permissions = EnumSet.noneOf(Permission.class);
        if (access.canPrint()) {
            permissions.add(Permission.PRINT);
        }
        if (access.canModify()) {
            permissions.add(Permission.MODIFY);
        }
        if (access.canExtractContent()) {
            permissions.add(Permission.EXTRACT_CONTENT);
        }
        if (access.canModifyAnnotations()) {
            permissions.add(Permission.ANNOTATE);
        }
        if (access.canFillInForm()) {
            permissions.add(Permission.FILL_FORMS);
        }
        if (access.canExtractForAccessibility()) {
            permissions.add(Permission.EXTRACT_FOR_ACCESSIBILITY);
        }
        if (access.canAssembleDocument()) {
            permissions.add(Permission.ASSEMBLE);
        }
        if (access.canPrintFaithful()) {
            permissions.add(Permission.PRINT_HIGH_QUALITY);
        }
        return permissions;
    }

    private static PageInfo readPageInfo(int number, PDPage page) {
        // PDPage#getRotation() already normalizes AND walks the page-tree
        // inheritance chain, but it silently maps an invalid (non-multiple-of-90)
        // raw value to 0 -- which would hide the anomaly. Reading the raw
        // inheritable attribute ourselves keeps the inheritance walk (needed for
        // a /Rotate set on an ancestor /Pages node) while still letting us see
        // and report the true raw value.
        COSBase rawRotate = PDPageTree.getInheritableAttribute(page.getCOSObject(), COSName.ROTATE);
        int rawRotation = (rawRotate instanceof COSNumber number1) ? number1.intValue() : 0;
        Rotation rotation = Rotation.tryFromDegrees(rawRotation).orElse(Rotation.DEG_0);

        Box mediaBox = toBox(page.getMediaBox());
        Box cropBox = toBox(page.getCropBox());
        Orientation orientation = Orientation.of(mediaBox, rotation);

        return new PageInfo(number, rawRotation, rotation, mediaBox, cropBox, orientation);
    }

    private static Box toBox(PDRectangle rectangle) {
        return new Box(rectangle.getLowerLeftX(), rectangle.getLowerLeftY(),
                rectangle.getUpperRightX(), rectangle.getUpperRightY());
    }

    private static String parseHeaderVersion(byte[] pdf) {
        String head = new String(pdf, 0, Math.min(pdf.length, HEADER_SEARCH_WINDOW), StandardCharsets.US_ASCII);
        Matcher matcher = HEADER_VERSION.matcher(head);
        if (!matcher.find()) {
            throw new InvalidPdfException(
                    "PDF header '%PDF-x.y' not found in the first " + HEADER_SEARCH_WINDOW + " bytes");
        }
        return matcher.group(1);
    }

    /**
     * Counts incremental update sections by counting non-overlapping
     * {@code %%EOF} markers in the raw bytes: one full save plus each
     * subsequent incremental save appends its own trailer ending in
     * {@code %%EOF}. This is a byte-level heuristic (a binary stream could
     * coincidentally contain the same bytes), acceptable for this reader;
     * falls back to 1 if, unexpectedly, no marker is found at all.
     */
    private static int countRevisions(byte[] pdf) {
        int count = 0;
        int index = 0;
        while ((index = indexOf(pdf, EOF_MARKER, index)) >= 0) {
            count++;
            index += EOF_MARKER.length;
        }
        return Math.max(count, 1);
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

    private static PDDocument load(byte[] pdf) {
        try {
            return Loader.loadPDF(pdf);
        } catch (InvalidPasswordException e) {
            throw new EncryptedPdfException("PDF is encrypted with a non-empty user password", e);
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to parse PDF", e);
        }
    }
}
