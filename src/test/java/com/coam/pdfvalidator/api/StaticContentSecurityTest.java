package com.coam.pdfvalidator.api;

import com.coam.pdfvalidator.infrastructure.web.CspHeaderFilter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
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
            + "script-src 'self'; connect-src 'self' wss://127.0.0.1:* https://127.0.0.1:*; "
            + "frame-src 'self' afirma:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

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

    /**
     * T11b: the vendored AutoScript library (loaded by the Firmar screen via
     * a same-origin {@code <script>} tag) must be reachable as a plain
     * static resource. It is intentionally outside {@link CspHeaderFilter}'s
     * exact-path allow-list -- a sub-resource's own response does not need
     * to carry the page's CSP header for {@code script-src 'self'} to permit
     * loading it, only the four protected paths above do.
     */
    @Test
    void theVendoredAutoScriptLibraryIsServedButNotAffectedByTheContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/vendor/autofirma/autoscript.js"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Content-Security-Policy"));
    }

    /**
     * T11d: {@link CspHeaderFilter#PROTECTED_PATHS} is matched with {@code
     * Set.contains} (exact string equality), never a prefix/substring check
     * -- regression guard proving a path that merely <em>looks like</em> one
     * of the four protected paths (a backup file sharing the same name, or
     * the name appearing as a path segment further down) is not swept in.
     * {@code /vendor/...} is included here even though it was never in the
     * allow-list to begin with (see the test above): the same exact-match
     * guarantee is what keeps a near-miss vendor path unaffected too.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/index.html.bak", "/api/v1/index.html", "/app.js.map", "/vendor/autofirma/autoscript.js.bak"})
    void aNearMissPathIsNotTreatedAsOneOfTheProtectedPaths(String path) throws Exception {
        mockMvc.perform(get(path)).andExpect(header().doesNotExist("Content-Security-Policy"));
    }

    /**
     * T11d: the static UI (html/js/css) must be served as UTF-8 -- README
     * §2.13's Spanish copy (tildes, ñ, "revocación", ...) must round-trip
     * correctly in the browser regardless of the client's own Accept-Charset
     * default. See {@link CspHeaderFilter}'s class Javadoc for why this is
     * forced here rather than through the global {@code
     * spring.servlet.encoding.force} property (that property would also force
     * a charset onto the JSON API, which {@link
     * #theAnalyzeApiEndpointIsServedAsBareApplicationJsonWithNoForcedCharset}
     * below guards against; {@link
     * com.coam.pdfvalidator.api.PdfAnalysisControllerTest} already covers the
     * success-path equivalent of that same guarantee).
     *
     * <p>{@code "/"} is deliberately not included here: Spring Boot's welcome
     * page mechanism resolves it to an internal {@code forward:index.html},
     * which {@code MockMvc} under {@code @SpringBootTest} never actually
     * executes (the forwarded response comes back with no content type/body
     * at all in this test harness, independently of {@link CspHeaderFilter}
     * -- a test-infrastructure limitation, not a production gap: the same
     * {@code Content-Security-Policy} header assertion above for {@code "/"}
     * still passes, because the filter sets headers on the original response
     * before the never-executed forward). {@link CspHeaderFilterTest}'s
     * {@code theUtf8CharsetIsForcedOnlyOnTheProtectedWelcomePage} covers
     * {@code "/"} directly against the filter instead, bypassing MockMvc's
     * forward handling entirely.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/index.html", "/app.js", "/styles.css"})
    void theStaticUiIsServedWithUtf8Charset(String path) throws Exception {
        MvcResult result = mockMvc.perform(get(path)).andExpect(status().isOk()).andReturn();

        assertThat(result.getResponse().getContentType()).containsIgnoringCase("charset=utf-8");
    }

    /**
     * T11d: the analysis API's JSON responses must never pick up the static
     * UI's forced UTF-8 charset (see {@link #theStaticUiIsServedWithUtf8Charset}
     * above and {@link CspHeaderFilter}'s class Javadoc). Uploads a
     * non-PDF-content file (real {@link PdfAnalysisExceptionHandler} error
     * path, exercised through the whole filter chain, not a slice test) to
     * get a genuine JSON error body rather than the content-type-less 415
     * from an empty request.
     */
    @Test
    void theAnalyzeApiEndpointIsServedAsBareApplicationJsonWithNoForcedCharset() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "not-a-pdf.txt", "text/plain", "hello".getBytes());

        MvcResult result = mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().is4xxClientError())
                .andReturn();

        // The error path returns RFC 7807 application/problem+json (see
        // PdfAnalysisExceptionHandler); PdfAnalysisControllerTest's success
        // path is the plain "application/json" one. Either way, bare -- no
        // charset parameter forced onto it.
        assertThat(result.getResponse().getContentType()).isEqualTo("application/problem+json");
    }

    /**
     * T16: both drop zones ("Validar" and "Firmar") tell the user the upload
     * limit, which must be the one the server actually enforces
     * ({@code spring.servlet.multipart.max-file-size}) -- the hint once kept
     * advertising 20 MB after the limit was raised to 80 MB.
     */
    @Test
    void theDropzoneHintsAdvertiseTheConfiguredUploadLimit(
            @Value("${spring.servlet.multipart.max-file-size}") String maxFileSize) throws Exception {
        String megabytes = maxFileSize.replaceAll("(?i)mb$", "");
        String expectedHint = "Solo archivos PDF, hasta " + megabytes + "&nbsp;MB.";

        String html = mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(html.split(Pattern.quote(expectedHint), -1)).hasSize(3);
        assertThat(html).doesNotContainPattern("hasta (?!" + megabytes + "&nbsp;MB)\\d+&nbsp;MB");
    }

    /**
     * T19: without a trusted timestamp the chain is validated at the analysis
     * time, and the UI must say so with the exact agreed wording; an untrusted
     * timestamp is flagged where it is shown. Rendering stays on
     * {@code textContent} and the UI never mentions the organisation.
     */
    @Test
    void theUiExplainsValidationAtCurrentTimeAndFlagsAnUntrustedTimestamp() throws Exception {
        String js = mockMvc.perform(get("/render.js"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(js).contains("VALIDATED_AT_CURRENT_TIME: \"Sin sello de tiempo de confianza: se ha validado a fecha de hoy\"");
        assertThat(js).contains("Sello de tiempo (TSA no de confianza)");
        assertThat(js).contains("timestamp.trusted");
        assertThat(js).doesNotContainPattern("\\.innerHTML\\s*=");
        assertThat(js.toLowerCase(java.util.Locale.ROOT)).doesNotContain("coam");
    }

    /** T20: the UI says so when the page table or the revision count is capped (textContent only, no COAM). */
    @Test
    void theUiFlagsTruncatedPagesAndALowerBoundRevisionCount() throws Exception {
        String js = mockMvc.perform(get("/render.js"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(js).contains("structure.pagesTruncated");
        assertThat(js).contains("structure.revisionCountLowerBound");
        assertThat(js).contains("Se muestran solo las primeras");
        assertThat(js).doesNotContainPattern("\\.innerHTML\\s*=");
        assertThat(js.toLowerCase(java.util.Locale.ROOT)).doesNotContain("coam");
    }
}
