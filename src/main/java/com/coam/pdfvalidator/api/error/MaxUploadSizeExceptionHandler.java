package com.coam.pdfvalidator.api.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.net.URI;

/**
 * Maps {@link MaxUploadSizeExceededException} to an RFC 9457 {@link
 * ProblemDetail} (413), the same body shape {@link PdfAnalysisExceptionHandler}
 * uses for every other error this API can produce.
 *
 * <h2>Why this cannot live in {@code PdfAnalysisExceptionHandler} (T09b)</h2>
 * Spring's {@code DispatcherServlet#doDispatch} resolves the multipart
 * request ({@code checkMultipart}) <em>before</em> it looks up the mapped
 * handler for the request. When the upload exceeds the configured limit,
 * {@link MaxUploadSizeExceededException} is therefore always thrown with no
 * handler yet resolved -- confirmed running the app locally: a 26 MB upload
 * produced a bare {@code 413} with an <b>empty body</b>, not the expected
 * {@code ProblemDetail}. An {@code @ExceptionHandler} scoped with {@code
 * assignableTypes = PdfAnalysisController.class} (as {@code
 * PdfAnalysisExceptionHandler} deliberately is, to avoid hijacking Spring's
 * own error handling for unrelated requests -- see that class's Javadoc)
 * only ever applies once a handler has actually been resolved, so it can
 * never see this particular exception.
 *
 * <p>This advice is deliberately left <b>unscoped</b> (no {@code
 * assignableTypes}/{@code basePackages}) so it is one of the advices Spring
 * still considers even when no handler has been resolved yet -- but it only
 * reacts to this one specific, always-safe exception type, so it cannot
 * repeat {@code PdfAnalysisExceptionHandler}'s original bug of hijacking
 * unrelated requests (e.g. a disabled Actuator endpoint's {@code 404}):
 * {@link MaxUploadSizeExceededException} is never thrown by any of those.
 */
@RestControllerAdvice
public class MaxUploadSizeExceptionHandler {

    private static final URI FILE_TOO_LARGE = URI.create("urn:pdfvalidator:error:file-too-large");

    /** The upload exceeds the configured maximum size (see {@code spring.servlet.multipart.max-file-size}). */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ProblemDetail handleTooLarge(MaxUploadSizeExceededException exception) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.PAYLOAD_TOO_LARGE, "The uploaded file exceeds the maximum allowed size.");
        problemDetail.setType(FILE_TOO_LARGE);
        return problemDetail;
    }
}
