package com.coam.pdfvalidator.infrastructure.preflight;

import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaIssue;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link PreflightPdfaValidator} against real fixtures: a formal PDF/A-1b
 * validator built on Apache PDFBox's {@code preflight} module.
 */
class PreflightPdfaValidatorTest {

    private final PreflightPdfaValidator validator = new PreflightPdfaValidator();

    /**
     * {@link TestPdfFactory#unsigned()} has no {@code OutputIntent}, no
     * embedded font (its text uses a standard, non-embedded Helvetica), and
     * no PDF/A XMP identification -- real, specific {@code preflight} error
     * codes captured empirically (not assumed) via a throwaway probe run
     * against this exact fixture before writing this assertion: {@code
     * 3.1.3} (font not embedded), {@code 2.4.3} (a color operator used
     * without an output/color profile), and {@code 7.1} (no PDF/A
     * metadata).
     */
    @Test
    void anOrdinaryUnsignedPdfWithNoOutputIntentOrXmpIsNonCompliant() throws Exception {
        byte[] pdf = TestPdfFactory.unsigned();

        PdfaReport report = validator.validate(pdf);

        assertThat(report.status()).isEqualTo(PdfaValidationStatus.NON_COMPLIANT);
        assertThat(report.issues().stream().map(PdfaIssue::code))
                .contains("3.1.3", "2.4.3", "7.1");
        assertThat(report.declaration().isDeclared()).isFalse();
    }

    @Test
    void corruptInputIsNotValidatedWithAnExplanatoryIssue() throws Exception {
        byte[] pdf = TestPdfFactory.corrupt();

        PdfaReport report = validator.validate(pdf);

        assertThat(report.status()).isEqualTo(PdfaValidationStatus.NOT_VALIDATED);
        assertThat(report.issues()).isNotEmpty();
    }

    @Test
    void encryptedInputIsNotValidatedRatherThanThrowing() throws Exception {
        byte[] pdf = TestPdfFactory.encrypted("owner-secret", "user-secret");

        PdfaReport report = validator.validate(pdf);

        assertThat(report.status()).isEqualTo(PdfaValidationStatus.NOT_VALIDATED);
        assertThat(report.issues()).anyMatch(issue -> issue.code().equals("ENCRYPTED"));
    }

    /**
     * {@link TestPdfFactory#pdfA1bCompliant()}: a blank page (no font to
     * embed), an sRGB {@code OutputIntent}, and XMP {@code pdfaid}
     * identification. Skipped when the local sRGB ICC profile this fixture
     * needs is not present on this machine (see {@code TestPdfFactory}'s
     * Javadoc) -- e.g. a non-Windows CI runner -- rather than failing;
     * documented as a known limitation of this fixture in the T07 progress
     * notes.
     */
    @Test
    void aMinimalDocumentWithOutputIntentAndXmpIdentificationIsCompliant() throws Exception {
        Assumptions.assumeTrue(TestPdfFactory.isPdfA1bCompliantFixtureAvailable(),
                "Local sRGB ICC profile not available on this machine; skipping");
        byte[] pdf = TestPdfFactory.pdfA1bCompliant();

        PdfaReport report = validator.validate(pdf);

        assertThat(report.status()).isEqualTo(PdfaValidationStatus.COMPLIANT);
        assertThat(report.issues()).isEmpty();
        assertThat(report.declaration()).isEqualTo(new PdfaDeclaration(1, "B"));
    }

    @Test
    void inputThatIsNotAPdfAtAllThrowsInvalidPdfException() {
        byte[] notAPdf = TestPdfFactory.notAPdf();

        assertThatThrownBy(() -> validator.validate(notAPdf)).isInstanceOf(InvalidPdfException.class);
    }
}
