package com.coam.pdfvalidator.api.error;

import com.coam.pdfvalidator.api.concurrency.AnalysisBusyException;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

class AnalysisBusyExceptionHandlerTest {

    @Test
    void mapsTo503WithStableTypeAndRetryAfterHeader() {
        ResponseEntity<ProblemDetail> response =
                new AnalysisBusyExceptionHandler().handleBusy(new AnalysisBusyException(5));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("5");
        ProblemDetail body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getStatus()).isEqualTo(503);
        assertThat(body.getType().toString()).isEqualTo("urn:pdfvalidator:error:busy");
        assertThat(body.getTitle()).isEqualTo("Service busy");
        assertThat(body.getDetail()).contains("busy").contains("try again");
    }
}
