package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;

/**
 * Formally validates a PDF against the PDF/A-1b conformance level -- and
 * only that level: no available PDFBox {@code preflight} implementation
 * formally validates PDF/A-2 or PDF/A-3, so this port deliberately does not
 * attempt to.
 *
 * <h2>Contract: this port never looks at the document's own PDF/A claim</h2>
 * {@link #validate(byte[])} always runs the PDF/A-1b formal validation
 * rules, regardless of what (if anything) the document's own XMP {@code
 * pdfaid} metadata declares -- it does not read that declaration to decide
 * <em>whether</em> to validate, only to report it back in the returned
 * {@link PdfaReport#declaration()} (via {@link PdfaDeclaration}), so the
 * caller never needs a second call to correlate the two. Consequently:
 * <ul>
 *   <li>A document declaring itself PDF/A-1b that also happens to satisfy
 *       the formal rules is reported {@link PdfaValidationStatus#COMPLIANT}.</li>
 *   <li>A document declaring itself PDF/A-2 or PDF/A-3 is still run through
 *       the PDF/A-1b rules by this port -- it will almost always fail them
 *       (later parts permit constructs 1b forbids), so this comes back
 *       {@link PdfaValidationStatus#NON_COMPLIANT} with 1b-specific issues
 *       that say nothing meaningful about the document's actual (2/3)
 *       conformance.</li>
 *   <li>A document declaring no PDF/A part at all is validated exactly the
 *       same way as one that does.</li>
 * </ul>
 * Interpreting that combination -- in particular, telling a caller "this is
 * PDF/A-2/3, only PDF/A-1b is formally validated here" rather than a
 * misleading "NON_COMPLIANT" -- is deliberately left to whatever composes
 * this port with {@link PdfDocumentReader#readPdfaDeclaration(byte[])} (the
 * analysis use case), not this port: keeping the port itself a single,
 * unconditional formal check keeps it simple to implement, test, and reason
 * about in isolation.
 */
public interface PdfaConformanceValidator {

    PdfaReport validate(byte[] pdf);
}
