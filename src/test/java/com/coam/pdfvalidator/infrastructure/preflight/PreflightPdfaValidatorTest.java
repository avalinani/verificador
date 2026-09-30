package com.coam.pdfvalidator.infrastructure.preflight;

import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaIssue;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import com.coam.pdfvalidator.infrastructure.pdfbox.DecodedSizeGuard;
import org.apache.pdfbox.preflight.ValidationResult;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

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
     * identification. {@code T07b}: the fixture's ICC profile now comes from
     * the JDK's own bundled sRGB profile instead of a Windows-only system
     * file, so this test runs (and asserts, never skips) on every platform,
     * including the Linux/Temurin CI runner.
     */
    @Test
    void aMinimalDocumentWithOutputIntentAndXmpIdentificationIsCompliant() throws Exception {
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

    /**
     * {@code T07b}: exercises the {@code probe.isEncrypted()} branch
     * directly (a document that opens without a password prompt but is
     * still encrypted), as opposed to {@link
     * #encryptedInputIsNotValidatedRatherThanThrowing()} above, which goes
     * through the {@code InvalidPasswordException} branch (a non-empty user
     * password).
     */
    @Test
    void encryptedWithEmptyUserPasswordIsNotValidatedRatherThanThrowing() throws Exception {
        byte[] pdf = TestPdfFactory.encryptedWithEmptyUserPassword();

        PdfaReport report = validator.validate(pdf);

        assertThat(report.status()).isEqualTo(PdfaValidationStatus.NOT_VALIDATED);
        assertThat(report.issues()).anyMatch(issue -> issue.code().equals("ENCRYPTED"));
    }

    /**
     * {@code T07b}: {@link PreflightPdfaValidator#mapErrors} directly, with
     * a synthetic list of more than {@link PreflightPdfaValidator#MAX_ISSUES}
     * distinct errors plus one exact duplicate -- constructing a real PDF
     * that trips 200+ distinct {@code preflight} error codes is impractical,
     * so this exercises the deduplication/truncation logic in isolation
     * (package-private on the validator specifically for this test).
     */
    @Test
    void moreThan200IssuesAreDeduplicatedAndTruncatedWithAMarker() {
        List<ValidationResult.ValidationError> errors = new ArrayList<>();
        for (int i = 0; i < 250; i++) {
            errors.add(new ValidationResult.ValidationError("CODE" + i, "detail " + i));
        }
        errors.add(new ValidationResult.ValidationError("CODE0", "detail 0")); // exact duplicate

        List<PdfaIssue> issues = PreflightPdfaValidator.mapErrors(errors, PreflightPdfaValidator.MAX_ISSUES);

        assertThat(issues).hasSize(PreflightPdfaValidator.MAX_ISSUES + 1);
        assertThat(issues.subList(0, PreflightPdfaValidator.MAX_ISSUES))
                .as("the duplicate must not have produced a 251st distinct issue before truncation")
                .extracting(PdfaIssue::code)
                .doesNotHaveDuplicates();
        PdfaIssue last = issues.get(issues.size() - 1);
        assertThat(last.code()).isEqualTo("TRUNCATED");
        assertThat(last.message()).contains("50");
    }

    /**
     * T18a: a decompression bomb (tiny on disk, huge once decoded) must be
     * reported as NOT_VALIDATED before preflight ever inflates it -- in
     * production the unbounded inflate exhausted the heap and, with
     * {@code -XX:+ExitOnOutOfMemoryError}, killed the JVM.
     */
    @Test
    void aDecompressionBombIsNotValidatedAsTooComplexInsteadOfExhaustingTheHeap() throws Exception {
        byte[] pdf = TestPdfFactory.decompressionBomb(1, 8 * 1024 * 1024);
        PreflightPdfaValidator bounded = new PreflightPdfaValidator(new DecodedSizeGuard.Limits(1024 * 1024, 64L * 1024 * 1024));

        PdfaReport report = bounded.validate(pdf);

        assertThat(report.status()).isEqualTo(PdfaValidationStatus.NOT_VALIDATED);
        assertThat(report.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.code()).isEqualTo("DOCUMENT_TOO_COMPLEX");
            assertThat(issue.message()).contains("decoded size limit");
        });
    }

    @Test
    void aBombInsideMetadataIsAlsoNotValidatedAsTooComplex() throws Exception {
        byte[] pdf = TestPdfFactory.decompressionBombInMetadata(8 * 1024 * 1024);
        PreflightPdfaValidator bounded = new PreflightPdfaValidator(new DecodedSizeGuard.Limits(1024 * 1024, 64L * 1024 * 1024));

        PdfaReport report = bounded.validate(pdf);

        assertThat(report.status()).isEqualTo(PdfaValidationStatus.NOT_VALIDATED);
        assertThat(report.issues()).extracting(PdfaIssue::code).containsExactly("DOCUMENT_TOO_COMPLEX");
    }

    // ---- T20: the issue limit is enforced while collecting ----

    private static List<ValidationResult.ValidationError> errors(String... codes) {
        List<ValidationResult.ValidationError> list = new ArrayList<>();
        for (String code : codes) {
            list.add(new ValidationResult.ValidationError(code, "detail " + code));
        }
        return list;
    }

    @Test
    void theIssueLimitIsConfigurableAndCountsOmittedIssues() {
        List<PdfaIssue> issues = PreflightPdfaValidator.mapErrors(errors("A", "B", "C", "D", "E", "F"), 3);

        assertThat(issues).extracting(PdfaIssue::code).containsExactly("A", "B", "C", "TRUNCATED");
        assertThat(issues.get(3).message()).isEqualTo("3 additional issue(s) omitted");
    }

    @Test
    void repeatedOccurrencesOfAnOmittedIssueAreCountedOnce() {
        List<PdfaIssue> issues = PreflightPdfaValidator.mapErrors(errors("A", "B", "C", "C", "C", "A"), 2);

        assertThat(issues).extracting(PdfaIssue::code).containsExactly("A", "B", "TRUNCATED");
        assertThat(issues.get(2).message()).isEqualTo("1 additional issue(s) omitted");
    }

    @Test
    void noMarkerIsAddedWhenEveryLaterErrorRepeatsAKeptIssue() {
        List<PdfaIssue> issues = PreflightPdfaValidator.mapErrors(errors("A", "B", "A", "B", "A"), 2);

        assertThat(issues).extracting(PdfaIssue::code).containsExactly("A", "B");
    }

    /**
     * The omitted issues are tracked only up to a fixed bound (so a report with millions of distinct errors
     * cannot grow a second unbounded set): beyond it the marker says "at least".
     */
    @Test
    void theOmittedCountIsALowerBoundOnceTheTrackingBoundIsExceeded() {
        String[] codes = new String[1300];
        for (int i = 0; i < codes.length; i++) {
            codes[i] = "CODE" + i;
        }

        List<PdfaIssue> issues = PreflightPdfaValidator.mapErrors(errors(codes), 3);

        assertThat(issues).hasSize(4);
        assertThat(issues.get(3).code()).isEqualTo("TRUNCATED");
        assertThat(issues.get(3).message()).isEqualTo("at least 1000 additional issue(s) omitted");
    }

    @Test
    void aValidatorBuiltWithAnIssueLimitAppliesItToItsReports() throws Exception {
        PreflightPdfaValidator capped = new PreflightPdfaValidator(DecodedSizeGuard.Limits.DEFAULT, 1);

        PdfaReport report = capped.validate(TestPdfFactory.unsigned());

        assertThat(report.issues().stream().filter(issue -> !issue.code().equals("TRUNCATED")).count())
                .isLessThanOrEqualTo(1);
    }
}
