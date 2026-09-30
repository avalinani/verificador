package com.coam.pdfvalidator.api.error;

import com.coam.pdfvalidator.api.PdfAnalysisController;
import com.coam.pdfvalidator.domain.exception.EncryptedPdfException;
import com.coam.pdfvalidator.domain.exception.InvalidPdfException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import java.net.URI;

/**
 * Maps every error {@code PdfAnalysisController} can produce to an RFC 9457
 * {@link ProblemDetail}, with a stable {@code type} URI per error kind
 * (documented in the README's error table) and no internal detail (stack
 * traces, exception messages) ever leaked for an unexpected failure.
 *
 * <p><b>Scoped to {@link PdfAnalysisController} only</b> ({@code
 * assignableTypes}): an unscoped {@code @RestControllerAdvice} applies to
 * every controller and to Spring MVC's own internal error dispatch for
 * unmatched requests -- confirmed the hard way running the app locally, an
 * unscoped catch-all {@code @ExceptionHandler(Exception.class)} intercepted
 * {@code NoResourceFoundException} for a disabled Actuator endpoint (e.g.
 * {@code /actuator/env}) and turned a correct {@code 404} into a leaking
 * {@code 500}. Scoping this advice to only the controller it exists for
 * leaves every other endpoint (Actuator, springdoc/swagger-ui, static
 * resources) on Spring Boot's own default error handling.
 *
 * <p><b>{@code MaxUploadSizeExceededException} is handled elsewhere (T09b)</b>:
 * that exception is always thrown before Spring resolves a handler for the
 * request (see {@link MaxUploadSizeExceptionHandler}'s Javadoc), so a
 * handler scoped here would never actually see it.
 */
@RestControllerAdvice(assignableTypes = PdfAnalysisController.class)
public class PdfAnalysisExceptionHandler {

    private static final System.Logger LOGGER = System.getLogger(PdfAnalysisExceptionHandler.class.getName());

    private static final URI MISSING_FILE = URI.create("urn:pdfvalidator:error:missing-file");
    private static final URI NOT_A_PDF = URI.create("urn:pdfvalidator:error:not-a-pdf");
    private static final URI CORRUPT_PDF = URI.create("urn:pdfvalidator:error:corrupt-pdf");
    private static final URI ENCRYPTED_PDF = URI.create("urn:pdfvalidator:error:encrypted-pdf");
    private static final URI INVALID_PARAMETER = URI.create("urn:pdfvalidator:error:invalid-parameter");
    private static final URI INTERNAL_ERROR = URI.create("urn:pdfvalidator:error:internal-error");

    /** No {@code file} part at all in the multipart request (a required {@link org.springframework.web.multipart.MultipartFile} parameter). */
    @ExceptionHandler({MissingServletRequestPartException.class, MissingServletRequestParameterException.class})
    public ProblemDetail handleMissingPart(Exception exception) {
        return problem(HttpStatus.BAD_REQUEST, MISSING_FILE, "Missing required 'file' part in the request.");
    }

    /**
     * A query parameter that cannot be converted (e.g. {@code checkRevocation=notabool}). Reports only the
     * parameter's declared name, never the client-supplied value.
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ProblemDetail handleInvalidParameter(MethodArgumentTypeMismatchException exception) {
        return problem(HttpStatus.BAD_REQUEST, INVALID_PARAMETER,
                "Invalid value for parameter '" + exception.getName() + "'.");
    }

    /** The {@code file} part is present but empty. */
    @ExceptionHandler(MissingFileException.class)
    public ProblemDetail handleMissingFile(MissingFileException exception) {
        return problem(HttpStatus.BAD_REQUEST, MISSING_FILE, exception.getMessage());
    }

    /** No recognizable {@code %PDF-} header at all, regardless of the uploaded file name. */
    @ExceptionHandler(NotAPdfException.class)
    public ProblemDetail handleNotAPdf(NotAPdfException exception) {
        return problem(HttpStatus.BAD_REQUEST, NOT_A_PDF, exception.getMessage());
    }

    /** A {@code %PDF-} header is present, but the document is otherwise corrupt/unparseable. */
    @ExceptionHandler(InvalidPdfException.class)
    public ProblemDetail handleInvalidPdf(InvalidPdfException exception) {
        return problem(HttpStatus.UNPROCESSABLE_ENTITY, CORRUPT_PDF,
                "The uploaded file could not be parsed as a valid PDF.");
    }

    /** The document requires a (non-empty) password to open. */
    @ExceptionHandler(EncryptedPdfException.class)
    public ProblemDetail handleEncryptedPdf(EncryptedPdfException exception) {
        return problem(HttpStatus.UNPROCESSABLE_ENTITY, ENCRYPTED_PDF,
                "The uploaded file is encrypted and cannot be analyzed without its password.");
    }

    /**
     * Anything else unexpected: logged for diagnosis (never the file's
     * content, only the failure itself), and reported with a generic
     * message -- never the exception's own message or a stack trace.
     */
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(Exception exception) {
        LOGGER.log(System.Logger.Level.ERROR, "Unexpected failure while analyzing a PDF", exception);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, INTERNAL_ERROR, "An unexpected error occurred.");
    }

    private static ProblemDetail problem(HttpStatus status, URI type, String detail) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, detail);
        problemDetail.setType(type);
        return problemDetail;
    }
}
