package com.coam.pdfvalidator.api;

import com.coam.pdfvalidator.infrastructure.web.CspHeaderFilter;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T11: the static "Validar" web UI is served with a Content-Security-Policy
 * header (README section on the web interface) -- scoped to exactly the
 * pages/scripts/styles that serve it, so Swagger UI and the analysis API
 * keep working unaffected (same "scope the advice narrowly" convention
 * already used for {@code PdfAnalysisExceptionHandler}/{@code
 * MaxUploadSizeExceptionHandler}).
 */
@SpringBootTest
@AutoConfigureMockMvc
class StaticContentSecurityTest {

    private static final String EXPECTED_CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            + "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void theWelcomePageIsServedWithTheContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", EXPECTED_CSP));
    }

    @Test
    void indexHtmlIsServedWithTheContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", EXPECTED_CSP));
    }

    @Test
    void appJsIsServedWithTheContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/app.js"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", EXPECTED_CSP));
    }

    @Test
    void stylesCssIsServedWithTheContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/styles.css"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", EXPECTED_CSP));
    }

    /** Swagger UI must keep working, unaffected by the header scoped to the static UI. */
    @Test
    void swaggerUiApiDocsAreNotAffectedByTheContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Content-Security-Policy"));
    }

    /**
     * T11c: the analysis API must never carry the static UI's CSP/charset
     * headers either -- the allow-list is exact-path, so this is really a
     * regression guard against a future, broader match (e.g. a prefix
     * check) accidentally catching {@code /api/**} too. The request itself
     * is missing its {@code file} part (400), which is irrelevant here:
     * {@link CspHeaderFilter} runs upstream of the controller and decides
     * before the request is even dispatched.
     */
    @Test
    void theAnalyzeApiEndpointIsNotAffectedByTheContentSecurityPolicy() throws Exception {
        mockMvc.perform(post("/api/v1/pdf/analyze"))
                .andExpect(header().doesNotExist("Content-Security-Policy"));
    }
}
