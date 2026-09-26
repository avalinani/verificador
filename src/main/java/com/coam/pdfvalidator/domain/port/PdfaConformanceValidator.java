package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.PdfaReport;

/** Validates a PDF against the PDF/A-1b conformance level. */
public interface PdfaConformanceValidator {

    PdfaReport validate(byte[] pdf);
}
