package com.coam.pdfvalidator.api;

import com.coam.pdfvalidator.api.dto.PdfAnalysisReportMapper;
import com.coam.pdfvalidator.application.AnalysisOptions;
import com.coam.pdfvalidator.application.AnalyzePdfUseCase;
import com.coam.pdfvalidator.domain.exception.EncryptedPdfException;
import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.DocumentHashes;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.domain.model.Permission;
import com.coam.pdfvalidator.domain.model.SecurityInfo;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.mock.web.MockMultipartHttpServletRequest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice test for {@link PdfAnalysisController}: {@link AnalyzePdfUseCase} is
 * stubbed via {@link MockitoBean} (a plain interface-free final class, but
 * Mockito's inline mock maker -- already active for this project's other
 * adapter tests -- mocks it like any other type), so every response/error
 * path is exercised without touching a real PDF adapter. {@link
 * PdfAnalysisReportMapper} is a plain {@code @Component}, outside {@code
 * @WebMvcTest}'s restricted web-layer component scan, so it is imported
 * explicitly.
 */
@WebMvcTest(controllers = PdfAnalysisController.class)
@Import(PdfAnalysisReportMapper.class)
class PdfAnalysisControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AnalyzePdfUseCase analyzePdfUseCase;

    private static final byte[] PDF_BYTES = "%PDF-1.7\n...".getBytes();

    private static com.coam.pdfvalidator.domain.model.PdfAnalysisReport minimalReport() {
        DocumentStructure structure = new DocumentStructure("1.7", null, 0, List.of(), 1);
        SecurityInfo security = new SecurityInfo(false, EnumSet.noneOf(Permission.class));
        PdfaReport pdfa = new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of());
        return new com.coam.pdfvalidator.domain.model.PdfAnalysisReport(
                "test.pdf", PDF_BYTES.length, new DocumentHashes("a".repeat(64), "b".repeat(128)), structure,
                security, pdfa, List.of(), Instant.parse("2026-09-27T10:00:00Z"), List.of());
    }

    @Test
    void aValidUploadReturns200WithTheMappedReport() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenReturn(minimalReport());

        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", PDF_BYTES);

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file).param("checkRevocation", "true"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.fileName").value("test.pdf"))
                .andExpect(jsonPath("$.hashes.sha256").value("a".repeat(64)))
                .andExpect(jsonPath("$.pdfa.status").value("NOT_VALIDATED"))
                .andExpect(jsonPath("$.sectionErrors").isEmpty());

        verify(analyzePdfUseCase).analyze(eq("test.pdf"), eq(PDF_BYTES), eq(new AnalysisOptions(true)));
    }

    @Test
    void checkRevocationDefaultsToFalseWhenOmitted() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenReturn(minimalReport());

        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", PDF_BYTES);

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().isOk());

        verify(analyzePdfUseCase).analyze(eq("test.pdf"), eq(PDF_BYTES), eq(new AnalysisOptions(false)));
    }

    @Test
    void missingFilePartReturns400() throws Exception {
        mockMvc.perform(multipart("/api/v1/pdf/analyze"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:pdfvalidator:error:missing-file"));
    }

    @Test
    void emptyFilePartReturns400() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", new byte[0]);

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:pdfvalidator:error:missing-file"));
    }

    @Test
    void contentWithoutAPdfHeaderReturns400EvenWithAPdfFileName() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "totally-a-pdf.pdf", "application/pdf", "not a pdf at all".getBytes());

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:pdfvalidator:error:not-a-pdf"));
    }

    @Test
    void aCorruptPdfWithAValidHeaderReturns422() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenThrow(new InvalidPdfException("truncated"));

        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", PDF_BYTES);

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.type").value("urn:pdfvalidator:error:corrupt-pdf"));
    }

    @Test
    void anEncryptedPdfReturns422() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenThrow(new EncryptedPdfException("needs a password"));

        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", PDF_BYTES);

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.type").value("urn:pdfvalidator:error:encrypted-pdf"));
    }

    /**
     * T09b: {@code MultipartFile#getBytes()} throwing {@code IOException} is
     * not a client-input problem like a missing/empty file (the client did
     * upload a part; this server failed to read its own temporary multipart
     * storage back) -- it must be reported as an unexpected failure (500),
     * not misclassified as {@code missing-file} (400), and must never leak
     * the underlying exception's own message. {@link #readContent} is
     * exercised directly here (a genuine {@code IOException} from a servlet
     * container's real multipart handling is impractical to trigger through
     * {@code MockMvc}, which always resolves a normal in-memory {@code
     * MockMultipartFile} instead); {@link
     * #anUploadReadIoExceptionDuringARealRequestReturns500WithoutLeakingItsMessage}
     * below proves the same {@code IOException} actually reaches HTTP 500
     * through the full controller + exception-handler stack (T09d follow-up).
     */
    @Test
    void anUploadReadIoExceptionIsReportedAsAnUnexpectedFailureNotAMissingFile() throws IOException {
        MultipartFile hostileFile = mock(MultipartFile.class);
        when(hostileFile.isEmpty()).thenReturn(false);
        when(hostileFile.getBytes()).thenThrow(new IOException("temp storage unreadable: /var/tmp/upload-9f2"));

        assertThatThrownBy(() -> PdfAnalysisController.readContent(hostileFile))
                .isInstanceOf(PdfAnalysisController.UploadReadException.class)
                .satisfies(exception -> assertThat(exception.getMessage())
                        .doesNotContain("temp storage unreadable")
                        .doesNotContain("/var/tmp"));
    }

    /**
     * T09d follow-up (review advisory): the unit-level proof above only
     * shows what {@link #readContent} itself does with the {@code
     * IOException} -- it never proves the exception actually reaches the
     * client as an HTTP 500 through the real controller method and {@code
     * PdfAnalysisExceptionHandler}. A hostile {@link MultipartFile} mock
     * (whose {@code getBytes()} throws) is injected directly into a real
     * {@link MockMultipartHttpServletRequest} via a {@code
     * RequestPostProcessor} -- {@code MockMvc}'s own {@code .file(...)}
     * builder only accepts a concrete {@code MockMultipartFile}, which
     * cannot be made to throw, so the request is built normally and then
     * this one part is added to it directly, exactly as a real servlet
     * container's {@code MultipartHttpServletRequest} would expose an
     * unreadable part to {@code @RequestParam MultipartFile} resolution.
     */
    @Test
    void anUploadReadIoExceptionDuringARealRequestReturns500WithoutLeakingItsMessage() throws Exception {
        MultipartFile hostileFile = mock(MultipartFile.class);
        when(hostileFile.getName()).thenReturn("file");
        when(hostileFile.isEmpty()).thenReturn(false);
        when(hostileFile.getBytes()).thenThrow(new IOException("temp storage unreadable: /var/tmp/upload-9f2"));

        MvcResult result = mockMvc.perform(multipart("/api/v1/pdf/analyze")
                        .with(request -> {
                            if (request instanceof MockMultipartHttpServletRequest multipartRequest) {
                                multipartRequest.addFile(hostileFile);
                            }
                            return request;
                        }))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.type").value("urn:pdfvalidator:error:internal-error"))
                .andReturn();

        assertThat(result.getResponse().getContentAsString())
                .doesNotContain("temp storage unreadable")
                .doesNotContain("/var/tmp");
        // T10 follow-up (T09d review advisory): proves this 500 is actually
        // caused by the upload-read IOException path itself -- not, say, a
        // coincidental failure elsewhere that happens to also return 500 --
        // by asserting the use case (which would only ever be reached once
        // the upload was successfully read) was never invoked at all.
        verify(analyzePdfUseCase, never()).analyze(anyString(), any(byte[].class), any(AnalysisOptions.class));
    }

    @Test
    void anUnexpectedFailureReturns500WithoutLeakingItsMessage() throws Exception {
        when(analyzePdfUseCase.analyze(anyString(), any(byte[].class), any(AnalysisOptions.class)))
                .thenThrow(new IllegalStateException("internal jdbc://secret-host detail"));

        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", PDF_BYTES);

        mockMvc.perform(multipart("/api/v1/pdf/analyze").file(file))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.type").value("urn:pdfvalidator:error:internal-error"))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("secret-host"))));
    }
}
