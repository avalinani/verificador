package com.coam.pdfvalidator.api;

import com.coam.pdfvalidator.api.dto.PdfAnalysisReportDto;
import com.coam.pdfvalidator.api.dto.PdfAnalysisReportMapper;
import com.coam.pdfvalidator.api.error.MissingFileException;
import com.coam.pdfvalidator.api.error.NotAPdfException;
import com.coam.pdfvalidator.application.AnalysisOptions;
import com.coam.pdfvalidator.application.AnalyzePdfUseCase;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The single REST endpoint of this service: upload a PDF, get back its full
 * analysis report as JSON. Never exposes a domain type directly -- {@link
 * PdfAnalysisReportMapper} produces an explicit {@link PdfAnalysisReportDto}
 * for every response -- and never trusts the uploaded file's name, only its
 * actual bytes (see {@link #looksLikePdf(byte[])}).
 */
@RestController
public class PdfAnalysisController {

    private static final System.Logger LOGGER = System.getLogger(PdfAnalysisController.class.getName());

    /** Matches {@code PdfBoxDocumentReader}'s own header search window (README section 2.4). */
    private static final int HEADER_SEARCH_WINDOW = 1024;
    private static final byte[] PDF_HEADER = "%PDF-".getBytes(StandardCharsets.US_ASCII);

    private final AnalyzePdfUseCase analyzePdfUseCase;
    private final PdfAnalysisReportMapper mapper;

    public PdfAnalysisController(AnalyzePdfUseCase analyzePdfUseCase, PdfAnalysisReportMapper mapper) {
        this.analyzePdfUseCase = analyzePdfUseCase;
        this.mapper = mapper;
    }

    @Operation(
            summary = "Analyze a PDF document",
            description = "Runs a single-pass technical/forensic audit of an uploaded PDF: signature integrity "
                    + "(PAdES/CMS) and post-signature modification detection, RFC 3161 timestamps, X.509 chain "
                    + "trust, optional OCSP/CRL revocation, PDF/A-1b conformance, and physical page properties. "
                    + "The service is stateless: the uploaded content is never stored.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Analysis completed",
                    content = @Content(schema = @Schema(implementation = PdfAnalysisReportDto.class))),
            @ApiResponse(responseCode = "400", description = "Missing/empty 'file' part, or the content has no "
                    + "recognizable PDF header",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
            @ApiResponse(responseCode = "422", description = "The file has a PDF header but is corrupt, or is "
                    + "encrypted with a non-empty password",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
            @ApiResponse(responseCode = "413", description = "The file exceeds the configured maximum upload size",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
            @ApiResponse(responseCode = "500", description = "Unexpected server error",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
    })
    @PostMapping(path = "/api/v1/pdf/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public PdfAnalysisReportDto analyze(
            @Parameter(description = "The PDF file to analyze (multipart/form-data field 'file').")
            @RequestParam("file") MultipartFile file,
            @Parameter(description = "Whether to check the signer certificate chain for revocation (OCSP/CRL). "
                    + "Network-bound and optional: disabled by default.")
            @RequestParam(name = "checkRevocation", defaultValue = "false") boolean checkRevocation) {
        byte[] content = readContent(file);
        if (!looksLikePdf(content)) {
            throw new NotAPdfException(
                    "The uploaded content does not start with a recognizable %PDF- header.");
        }

        PdfAnalysisReport report = analyzePdfUseCase.analyze(
                file.getOriginalFilename(), content, new AnalysisOptions(checkRevocation));
        return mapper.toDto(report);
    }

    /**
     * @throws MissingFileException if the {@code file} part is absent or
     *                              empty -- a client-input problem (400)
     * @throws UploadReadException if the part is present but its bytes could
     *                              not be read (T09b): unlike a missing/empty
     *                              part, this is not a client-input problem
     *                              (the client did upload a file part; this
     *                              server could not read the bytes back from
     *                              its own temporary multipart storage), so
     *                              it is reported as an unexpected failure
     *                              (500) via {@code
     *                              PdfAnalysisExceptionHandler#handleUnexpected}
     *                              rather than misclassified as a missing file
     */
    static byte[] readContent(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new MissingFileException("The 'file' part is missing or empty.");
        }
        try {
            return file.getBytes();
        } catch (IOException e) {
            LOGGER.log(System.Logger.Level.WARNING, "Failed to read the uploaded file's bytes", e);
            throw new UploadReadException("The uploaded file's part could not be read", e);
        }
    }

    /** See {@link #readContent}'s Javadoc for why this is 500, not 400. */
    static final class UploadReadException extends RuntimeException {
        UploadReadException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * True when a {@code %PDF-} header appears within the first {@link
     * #HEADER_SEARCH_WINDOW} bytes -- the same window {@code
     * PdfBoxDocumentReader} itself searches, so a document this check
     * accepts is exactly one the PDF engine would also consider to have a
     * header (whether or not the rest of it later turns out to be broken).
     * Deliberately ignores the uploaded file name: a {@code .pdf}-named file
     * with non-PDF content is still rejected here.
     */
    private static boolean looksLikePdf(byte[] content) {
        int window = Math.min(content.length, HEADER_SEARCH_WINDOW);
        outer:
        for (int i = 0; i <= window - PDF_HEADER.length; i++) {
            for (int j = 0; j < PDF_HEADER.length; j++) {
                if (content[i + j] != PDF_HEADER[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
