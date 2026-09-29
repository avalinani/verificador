package com.coam.pdfvalidator.api;

import com.coam.pdfvalidator.fixtures.TestPdfFactory;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The one full end-to-end test (README/T09 requirement): the real Spring
 * context, every real adapter wired through {@code AdapterConfiguration}/
 * {@code UseCaseConfiguration}, and a real signed-and-timestamped PDF
 * (produced entirely in memory by {@link TestPdfFactory}, never a file on
 * disk) uploaded through {@link MockMvc}. Also doubles as the context-loads
 * check for {@code /v3/api-docs}, since both need the same (expensive) full
 * application context.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PdfAnalysisEndToEndTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void aSignedAndTimestampedPdfIsAnalyzedEndToEnd() throws Exception {
        byte[] pdf = TestPdfFactory.signedWithTimestamp();
        MockMultipartFile file = new MockMultipartFile(
                "file", "signed-with-timestamp.pdf", "application/pdf", pdf);

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fileName").value("signed-with-timestamp.pdf"))
                .andExpect(jsonPath("$.sizeBytes").value(pdf.length))
                .andExpect(jsonPath("$.hashes.sha256").isString())
                .andExpect(jsonPath("$.structure.pageCount").value(1))
                .andExpect(jsonPath("$.signatures.length()").value(1))
                .andExpect(jsonPath("$.signatures[0].integrity").value("INTACT"))
                .andExpect(jsonPath("$.signatures[0].coverage.coversWholeDocument").value(true))
                .andExpect(jsonPath("$.signatures[0].timestamp.present").value(true))
                .andExpect(jsonPath("$.signatures[0].timestamp.imprintValid").value(true))
                .andExpect(jsonPath("$.signatures[0].timestamp.signatureValid").value(true))
                // Not in this test's own trust store: chain validation ran, but the
                // test CA is (correctly) not one of the bundled trust anchors.
                .andExpect(jsonPath("$.signatures[0].chainStatus").value("UNTRUSTED_ROOT"))
                .andExpect(jsonPath("$.sectionErrors").isEmpty());
    }

    @Test
    void openApiDocsAreExposedAndDescribeTheAnalyzeEndpoint() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/pdf/analyze']").exists())
                .andExpect(jsonPath("$.info.title").value("PDF Inspector & Signature Verifier API"))
                .andExpect(jsonPath("$.info.license.name").value("GPL-3.0"));
    }

    @Test
    void healthAndInfoAreExposedButOtherActuatorEndpointsAreNot() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        mockMvc.perform(get("/actuator/info")).andExpect(status().isOk());
        // Regression: PdfAnalysisExceptionHandler's @RestControllerAdvice, if left
        // unscoped, hijacks Spring MVC's own default error handling for a request
        // that never reaches PdfAnalysisController and turns this correct 404 into
        // a leaking 500 -- found running the app locally, see that class's Javadoc.
        mockMvc.perform(get("/actuator/env")).andExpect(status().isNotFound());
    }
}
