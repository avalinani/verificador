package com.coam.pdfvalidator.api.error;

import com.coam.pdfvalidator.domain.exception.EncryptedPdfException;
import com.coam.pdfvalidator.domain.exception.InvalidPdfException;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises every {@code @ExceptionHandler} mapping directly (plain method
 * calls, no Spring context or MockMvc): deterministic and independent of
 * whatever a mocked servlet container's own multipart-size enforcement
 * happens to do -- {@code PdfAnalysisControllerTest} covers the same
 * mappings again end-to-end through real HTTP requests.
 */
class PdfAnalysisExceptionHandlerTest {

    private final PdfAnalysisExceptionHandler handler = new PdfAnalysisExceptionHandler();

    @Test
    void missingServletRequestPartMapsTo400MissingFile() {
        ProblemDetail problem = handler.handleMissingPart(
                new MissingServletRequestPartException("file"));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:missing-file");
    }

    @Test
    void missingServletRequestParameterMapsTo400MissingFile() {
        ProblemDetail problem = handler.handleMissingPart(
                new MissingServletRequestParameterException("file", "MultipartFile"));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:missing-file");
    }

    @Test
    void emptyFileExceptionMapsTo400MissingFile() {
        ProblemDetail problem = handler.handleMissingFile(new MissingFileException("empty"));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:missing-file");
        assertThat(problem.getDetail()).isEqualTo("empty");
    }

    @Test
    void notAPdfExceptionMapsTo400NotAPdf() {
        ProblemDetail problem = handler.handleNotAPdf(new NotAPdfException("no header"));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:not-a-pdf");
    }

    @Test
    void invalidPdfExceptionMapsTo422CorruptPdf() {
        ProblemDetail problem = handler.handleInvalidPdf(new InvalidPdfException("corrupt"));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:corrupt-pdf");
        // The domain exception's own message must not leak verbatim.
        assertThat(problem.getDetail()).doesNotContain("corrupt");
    }

    @Test
    void encryptedPdfExceptionMapsTo422EncryptedPdf() {
        ProblemDetail problem = handler.handleEncryptedPdf(new EncryptedPdfException("needs a password"));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:encrypted-pdf");
    }

    // MaxUploadSizeExceededException is handled by MaxUploadSizeExceptionHandler
    // instead (T09b): see MaxUploadSizeExceptionHandlerTest and that class's
    // Javadoc for why it cannot be handled here.

    @Test
    void unexpectedExceptionMapsTo500WithoutLeakingItsMessage() {
        ProblemDetail problem = handler.handleUnexpected(
                new IllegalStateException("connection string: jdbc://secret-internal-host/db"));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:internal-error");
        assertThat(problem.getDetail()).doesNotContain("secret-internal-host");
    }
}
