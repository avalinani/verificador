package com.coam.pdfvalidator.api.error;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plain unit test for the handler method itself; {@code
 * MaxUploadSizeExceptionHandlerIntegrationTest} proves the real HTTP
 * response actually carries this body (T09b: it previously did not, see
 * {@link MaxUploadSizeExceptionHandler}'s Javadoc).
 */
class MaxUploadSizeExceptionHandlerTest {

    private final MaxUploadSizeExceptionHandler handler = new MaxUploadSizeExceptionHandler();

    @Test
    void maxUploadSizeExceededMapsTo413FileTooLarge() {
        ProblemDetail problem = handler.handleTooLarge(new MaxUploadSizeExceededException(20_000_000L));

        assertThat(problem.getStatus()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE.value());
        assertThat(problem.getType().toString()).isEqualTo("urn:pdfvalidator:error:file-too-large");
        assertThat(problem.getDetail()).isNotBlank();
    }
}
