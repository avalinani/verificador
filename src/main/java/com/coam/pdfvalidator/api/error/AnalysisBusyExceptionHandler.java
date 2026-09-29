package com.coam.pdfvalidator.api.error;

import com.coam.pdfvalidator.api.concurrency.AnalysisBusyException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;

/**
 * Maps {@link AnalysisBusyException} to a {@code 503} {@link ProblemDetail}
 * with a {@code Retry-After} header. Deliberately unscoped, like {@link
 * MaxUploadSizeExceptionHandler}: the exception is raised by the bulkhead
 * servlet filter, before any controller handler has been resolved, so an
 * {@code assignableTypes}-scoped advice would never see it. It reacts to this
 * one exception type only.
 */
@RestControllerAdvice
public class AnalysisBusyExceptionHandler {

    private static final URI BUSY = URI.create("urn:pdfvalidator:error:busy");

    @ExceptionHandler(AnalysisBusyException.class)
    public ResponseEntity<ProblemDetail> handleBusy(AnalysisBusyException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE,
                "The service is busy analyzing other documents. Please try again in a few seconds.");
        problem.setType(BUSY);
        problem.setTitle("Service busy");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(exception.retryAfterSeconds()))
                .body(problem);
    }
}
