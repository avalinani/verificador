package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.SecurityInfo;

/**
 * Reads structural, security and PDF/A-declaration properties out of a PDF.
 * Split from {@code SignatureVerifier} and {@code PdfaConformanceValidator}
 * (interface segregation): a caller that only needs page geometry should not
 * have to depend on signature or PDF/A validation.
 */
public interface PdfDocumentReader {

    DocumentStructure readStructure(byte[] pdf);

    SecurityInfo readSecurity(byte[] pdf);

    PdfaDeclaration readPdfaDeclaration(byte[] pdf);
}
