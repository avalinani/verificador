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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
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
