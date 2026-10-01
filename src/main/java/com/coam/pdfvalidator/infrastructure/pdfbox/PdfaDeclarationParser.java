package com.coam.pdfvalidator.infrastructure.pdfbox;

import com.coam.pdfvalidator.domain.model.PdfaDeclaration;

import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.xmpbox.XMPMetadata;
import org.apache.xmpbox.schema.PDFAIdentificationSchema;
import org.apache.xmpbox.xml.DomXmpParser;
import org.apache.xmpbox.xml.XmpParsingException;

import java.io.IOException;

/**
 * Reads the {@code pdfaid} XMP identification (PDF/A part and conformance) from a document's metadata stream.
 * Shared by the document reader and the PDF/A validator, which both need the declaration and must agree on it.
 */
public final class PdfaDeclarationParser {

    private PdfaDeclarationParser() {
    }

    /**
     * The declaration found in {@code metadata}, or {@link PdfaDeclaration#NONE} when the XMP carries none or
     * cannot be decoded within {@code maxStreamBytes} or parsed: malformed XMP is not itself the PDF content, so
     * it counts as "no PDF/A declaration" rather than aborting the analysis.
     */
    public static PdfaDeclaration parse(PDMetadata metadata, long maxStreamBytes) {
        try {
            byte[] xmpBytes = DecodedSizeGuard.decode(metadata.getCOSObject(), maxStreamBytes);
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
            return PdfaDeclaration.NONE;
        }
    }
}
