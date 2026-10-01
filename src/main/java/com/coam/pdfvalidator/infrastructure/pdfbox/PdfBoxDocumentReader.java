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
import org.apache.pdfbox.cos.COSFloat;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;

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
public final class PdfBoxDocumentReader implements PdfDocumentReader {

    private final DecodedSizeGuard.Limits limits;
    private final StructureLimits structureLimits;

    public PdfBoxDocumentReader() {
        this(DecodedSizeGuard.Limits.DEFAULT);
    }

    public PdfBoxDocumentReader(DecodedSizeGuard.Limits limits) {
        this(limits, StructureLimits.DEFAULT);
    }

    public PdfBoxDocumentReader(DecodedSizeGuard.Limits limits, StructureLimits structureLimits) {
        this.limits = java.util.Objects.requireNonNull(limits, "limits");
        this.structureLimits = java.util.Objects.requireNonNull(structureLimits, "structureLimits");
    }


    private static final Pattern HEADER_VERSION = Pattern.compile("%PDF-(\\d\\.\\d)");
    private static final int HEADER_SEARCH_WINDOW = 1024;

    @Override
    public DocumentStructure readStructure(byte[] pdf) {
        try (PDDocument document = load(pdf)) {
            String headerVersion = parseHeaderVersion(pdf);
            PDDocumentCatalog catalog = document.getDocumentCatalog();
            String catalogVersion = catalog.getVersion();

            // T20: details are read for the first maxPages pages only; the rest are merely counted, so a
            // hostile page tree cannot build an unbounded in-memory list (nor, later, an unbounded JSON body).
            List<PageInfo> pages = new ArrayList<>();
            int pageCount = 0;
            for (PDPage page : document.getPages()) {
                pageCount++;
                if (pageCount <= structureLimits.maxPages()) {
                    pages.add(readPageInfo(pageCount, page));
                }
            }

            RevisionCounter.RevisionCount revisions = RevisionCounter.count(pdf, structureLimits);
            return new DocumentStructure(headerVersion, catalogVersion, pageCount, pages, revisions.value(),
                    pageCount > pages.size(), revisions.lowerBound());
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
            return PdfaDeclarationParser.parse(metadata, limits.maxStreamBytes());
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to close PDF document after reading its PDF/A declaration", e);
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
        int rawRotation = rawRotationAsInt(rawRotate);
        boolean rotationValid = isValidRawRotation(rawRotate) && Rotation.tryFromDegrees(rawRotation).isPresent();
        Rotation rotation = rotationValid ? Rotation.fromDegrees(rawRotation) : Rotation.DEG_0;

        Box mediaBox = toBox(page.getMediaBox());
        Box cropBox = toBox(page.getCropBox());
        Orientation orientation = Orientation.of(mediaBox, rotation);

        return new PageInfo(number, rawRotation, rotationValid, rotation, mediaBox, cropBox, orientation);
    }

    /**
     * Best-effort integer view of a raw {@code /Rotate} value, for reporting
     * only. A missing entry (no {@code /Rotate}, {@code null}) defaults to 0;
     * an integral {@code COSInteger} or {@code COSFloat} is truncated to its
     * int value; anything else (a non-integral float, or a non-numeric
     * object) also defaults to 0 here -- {@link #isValidRawRotation} is the
     * one that actually flags those as invalid, so this truncation never
     * silently hides them as if they were a valid multiple of 90.
     */
    private static int rawRotationAsInt(COSBase rawRotate) {
        if (rawRotate instanceof COSInteger integer) {
            return integer.intValue();
        }
        if (rawRotate instanceof COSFloat floatValue) {
            return (int) floatValue.floatValue();
        }
        return 0;
    }

    /**
     * Only a {@code COSInteger}, or a {@code COSFloat} with no fractional
     * part (e.g. {@code 90.0}), is a trustworthy raw {@code /Rotate} value.
     * A non-integral real (e.g. {@code 90.5}) or any other, non-numeric
     * object is flagged invalid here -- never silently truncated into
     * looking like a valid multiple of 90. A missing {@code /Rotate}
     * ({@code null}) is valid: it simply means "not rotated" (0 degrees).
     */
    private static boolean isValidRawRotation(COSBase rawRotate) {
        if (rawRotate == null) {
            return true;
        }
        if (rawRotate instanceof COSInteger) {
            return true;
        }
        if (rawRotate instanceof COSFloat floatValue) {
            float value = floatValue.floatValue();
            return value == Math.rint(value);
        }
        return false;
    }

    private static Box toBox(PDRectangle rectangle) {
        return new Box(rectangle.getLowerLeftX(), rectangle.getLowerLeftY(),
                rectangle.getUpperRightX(), rectangle.getUpperRightY());
    }

    /**
     * Extracts the {@code %PDF-x.y} header version from the first bytes of
     * the file, or {@code null} when no such header is found. A missing
     * header does not abort the analysis: PDFBox (and real-world PDF
     * readers generally) can often still parse a document whose header is
     * missing, shifted, or otherwise non-conformant -- {@link #load} already
     * succeeded by the time this is called, so the document itself is
     * readable even though its declared version is unknown.
     */
    private static String parseHeaderVersion(byte[] pdf) {
        String head = new String(pdf, 0, Math.min(pdf.length, HEADER_SEARCH_WINDOW), StandardCharsets.US_ASCII);
        Matcher matcher = HEADER_VERSION.matcher(head);
        return matcher.find() ? matcher.group(1) : null;
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
