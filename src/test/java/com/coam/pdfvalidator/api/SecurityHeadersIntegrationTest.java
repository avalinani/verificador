package com.coam.pdfvalidator.api;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/** T18d: the hardening headers reach UI, API, error and Actuator responses in the full application. */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityHeadersIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @ParameterizedTest
    @ValueSource(strings = {"/", "/app.js", "/v3/api-docs", "/actuator/health", "/does-not-exist"})
    void getResponsesCarryTheHardeningHeaders(String path) throws Exception {
        mockMvc.perform(get(path))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/pdf/analyze"})
    void anApiErrorResponseCarriesTheHardeningHeaders(String path) throws Exception {
        mockMvc.perform(multipart(path))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }
}
