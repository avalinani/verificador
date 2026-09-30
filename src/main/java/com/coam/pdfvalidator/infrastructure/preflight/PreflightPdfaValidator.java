package com.coam.pdfvalidator.infrastructure.preflight;

import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaIssue;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.domain.port.PdfaConformanceValidator;

import com.coam.pdfvalidator.infrastructure.pdfbox.DecodedSizeGuard;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.preflight.Format;
import org.apache.pdfbox.preflight.PreflightDocument;
import org.apache.pdfbox.preflight.ValidationResult;
import org.apache.pdfbox.preflight.exception.SyntaxValidationException;
import org.apache.pdfbox.preflight.parser.PreflightParser;
import org.apache.xmpbox.XMPMetadata;
import org.apache.xmpbox.schema.PDFAIdentificationSchema;
import org.apache.xmpbox.xml.DomXmpParser;
import org.apache.xmpbox.xml.XmpParsingException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@link PdfaConformanceValidator} built on Apache PDFBox's {@code
 * preflight} module, validating strictly against the PDF/A-1b conformance
 * level (the only level {@code preflight} 3.0.8 supports formally
 * validating; see the port's own Javadoc for how a document declaring a
 * different PDF/A part or conformance level -- 2, 3, or "a" -- is meant to
 * be reported by the use case that composes this validator's result with
 * {@code PdfDocumentReader#readPdfaDeclaration}).
 *
 * <h2>Never throws for a single bad document</h2>
 * <b>Deliberately narrower than {@code PdfBoxDocumentReader}'s own
 * "unreadable input" case</b>: only input with no recognizable {@code
 * %PDF-x.y} header at all in its first bytes -- i.e. not shaped like a PDF
 * to begin with -- raises the domain's {@link InvalidPdfException}. {@code
 * PdfBoxDocumentReader.load()} throws that same exception more broadly, for
 * any input plain PDFBox cannot parse, including a truncated-but-header-
 * present file. This validator instead reports a header-present-but-broken
 * document (or one {@code preflight} itself crashes on) as {@link
 * PdfaValidationStatus#NOT_VALIDATED} with an explanatory {@link PdfaIssue},
 * never thrown -- a PDF/A conformance verdict for the surrounding analysis
 * pipeline is meaningful ("not validatable") even for a document broken past
 * the point plain PDFBox can open it, so it does not need the same hard
 * "abort" treatment the general-purpose reader gives it. Encryption is
 * likewise reported, never thrown: PDF/A forbids it outright, so it is
 * itself a conformance fact worth reporting rather than a reason to fail
 * the whole analysis.
 *
 * <h2>Design: a cheap gate before the real preflight parse</h2>
 * Before invoking {@code preflight} itself, this loads the document once
 * with plain {@link Loader#loadPDF(byte[])} purely to classify it: {@code
 * InvalidPasswordException} or {@link PDDocument#isEncrypted()} means
 * encrypted; any other {@link IOException} means header-present-but-broken
 * (reported, not thrown, per the design decision above). This costs a
 * second full parse in addition to {@code preflight}'s own -- a real, if
 * modest, performance concern for a module already documented as heavy;
 * left unmeasured per this task's own scope (memory/performance profiling is
 * T12's job), but noted here for whoever picks that up.
 */
public final class PreflightPdfaValidator implements PdfaConformanceValidator {

    /**
     * Caps how many issues a single report carries: a document with one
     * systemic problem (e.g. every page missing the same required resource)
     * can otherwise produce thousands of near-duplicate {@code preflight}
     * errors. Exact duplicates (same code and message) are also collapsed
     * to one entry as they are collected. Default; configurable through {@code pdfvalidator.analysis.max-pdfa-issues}.
     */
    static final int MAX_ISSUES = 200;

    /**
     * How many distinct omitted issues are remembered to report an exact omitted count (T20). Past it the
     * marker says "at least N", so memory stays bounded whatever the number of distinct errors.
     */
    private static final int MAX_TRACKED_OMITTED = 1000;

    private static final Pattern PDF_HEADER = Pattern.compile("%PDF-\\d\\.\\d");
    private static final int HEADER_SEARCH_WINDOW = 1024;

    private static final System.Logger LOGGER = System.getLogger(PreflightPdfaValidator.class.getName());

    private final DecodedSizeGuard.Limits limits;
    private final int maxIssues;

    /**
     * Logs the full failure server-side (T23a) so the report can carry a fixed text only. Parser messages can echo
     * attacker-controlled document content, so line breaks are replaced and the length is capped before logging
     * (no log-line forging); the stack trace is deliberately not logged. Package-private for direct unit testing.
     */
    static void logFailure(String what, Throwable failure) {
        LOGGER.log(System.Logger.Level.WARNING, () -> what + ": " + sanitizeForLog(failure));
    }

    static String sanitizeForLog(Throwable failure) {
        String text = failure.getClass().getName() + ": " + failure.getMessage();
        String flat = text.replaceAll("\\p{Cntrl}+", " ");
        return flat.length() > 300 ? flat.substring(0, 300) + "..." : flat;
    }

    public PreflightPdfaValidator() {
        this(DecodedSizeGuard.Limits.DEFAULT);
    }

    public PreflightPdfaValidator(DecodedSizeGuard.Limits limits) {
        this(limits, MAX_ISSUES);
    }

    public PreflightPdfaValidator(DecodedSizeGuard.Limits limits, int maxIssues) {
        this.limits = Objects.requireNonNull(limits, "limits");
        if (maxIssues < 1) {
            throw new IllegalArgumentException("maxIssues must be >= 1, got: " + maxIssues);
        }
        this.maxIssues = maxIssues;
    }

    @Override
    public PdfaReport validate(byte[] pdf) {
        Objects.requireNonNull(pdf, "pdf");

        if (!looksLikeAPdf(pdf)) {
            throw new InvalidPdfException(
                    "Input does not look like a PDF file (no %PDF-x.y header found in the first bytes)");
        }

        try (PDDocument probe = Loader.loadPDF(pdf)) {
            if (probe.isEncrypted()) {
                return notValidated(PdfaDeclaration.NONE,
                        "ENCRYPTED", "Encrypted documents cannot be validated for PDF/A-1b conformance");
            }
            // T18a: refuse decompression bombs before preflight inflates anything.
            DecodedSizeGuard.check(probe, limits);
        } catch (DecodedSizeGuard.LimitExceededException e) {
            return notValidated(PdfaDeclaration.NONE, "DOCUMENT_TOO_COMPLEX",
                    "The document is too complex to validate: " + e.getMessage());
        } catch (InvalidPasswordException e) {
            return notValidated(PdfaDeclaration.NONE,
                    "ENCRYPTED", "Encrypted documents cannot be validated for PDF/A-1b conformance");
        } catch (IOException e) {
            // Declares a PDF header but is otherwise broken: report, never
            // throw (see the class Javadoc for why this differs from
            // PdfBoxDocumentReader's own, broader "unreadable" case).
            logFailure("PDF/A probe could not parse the document", e);
            return notValidated(PdfaDeclaration.NONE, "NOT_VALIDATED",
                    "The document declares a PDF header but could not be parsed");
        } catch (RuntimeException e) {
            // T07b: plain PDFBox parsing (unlike preflight's own parse below)
            // is not otherwise guarded here, so a hostile/malformed document
            // that trips an unchecked exception during this cheap probe
            // (rather than an IOException) must not escape and abort the
            // whole analysis either.
            logFailure("PDF/A probe failed unexpectedly", e);
            return notValidated(PdfaDeclaration.NONE, "NOT_VALIDATED",
                    "The document declares a PDF header but could not be probed for encryption");
        }

        try (RandomAccessRead source = new RandomAccessReadBuffer(pdf)) {
            PreflightParser parser = new PreflightParser(source);
            PDDocument parsed;
            try {
                parsed = parser.parse(Format.PDF_A1B);
            } catch (SyntaxValidationException e) {
                return notValidated(PdfaDeclaration.NONE, syntaxErrorIssues(e, maxIssues));
            }
            try (PreflightDocument document = (PreflightDocument) parsed) {
                PdfaDeclaration declaration = readDeclaration(document);
                ValidationResult result = document.validate();
                if (result.isValid()) {
                    return new PdfaReport(declaration, PdfaValidationStatus.COMPLIANT, List.of());
                }
                return new PdfaReport(declaration, PdfaValidationStatus.NON_COMPLIANT, mapErrors(result.getErrorsList(), maxIssues));
            }
        } catch (IOException | RuntimeException e) {
            // A single malformed document must never abort the whole
            // analysis: any preflight-internal failure beyond a genuinely
            // unreadable PDF (excluded above, by isEncrypted()/the throw in
            // ensureParseable-equivalent below) is reported, never thrown.
            logFailure("PDF/A-1b validation failed", e);
            return notValidated(PdfaDeclaration.NONE, "NOT_VALIDATED", "PDF/A-1b validation failed");
        }
    }

    /**
     * Whether {@code pdf} at least declares a {@code %PDF-x.y} header in its
     * first bytes -- the narrow definition of "not a PDF at all" this
     * validator throws {@link InvalidPdfException} for (see the class
     * Javadoc). Mirrors {@code PdfBoxDocumentReader.parseHeaderVersion}'s own
     * search window/pattern, but only to answer "is it there", not to report
     * the version.
     */
    private static boolean looksLikeAPdf(byte[] pdf) {
        int window = Math.min(pdf.length, HEADER_SEARCH_WINDOW);
        String head = new String(pdf, 0, window, StandardCharsets.US_ASCII);
        return PDF_HEADER.matcher(head).find();
    }

    /**
     * Reads the {@code pdfaid} XMP identification directly from the
     * already-parsed {@link PreflightDocument}, independently of {@code
     * PdfDocumentReader.readPdfaDeclaration} -- deliberately duplicated
     * (rather than shared across infrastructure packages) to keep each
     * adapter package self-contained, matching this codebase's existing
     * convention (no {@code infrastructure.*} package depends on another).
     */
    private PdfaDeclaration readDeclaration(PDDocument document) {
        PDMetadata metadata = document.getDocumentCatalog().getMetadata();
        if (metadata == null) {
            return PdfaDeclaration.NONE;
        }
        try {
            byte[] xmpBytes = DecodedSizeGuard.decode(metadata.getCOSObject(), limits.maxStreamBytes());
            XMPMetadata xmp = new DomXmpParser().parse(xmpBytes);
            PDFAIdentificationSchema schema = xmp.getPDFAIdentificationSchema();
            if (schema == null) {
                return PdfaDeclaration.NONE;
            }
            Integer part = schema.getPart();
            String conformance = schema.getConformance();
            if (part == null || conformance == null) {
                return PdfaDeclaration.NONE;
            }
            return new PdfaDeclaration(part, conformance);
        } catch (IOException | XmpParsingException e) {
            return PdfaDeclaration.NONE;
        }
    }

    private static List<PdfaIssue> syntaxErrorIssues(SyntaxValidationException e, int maxIssues) {
        List<PdfaIssue> issues = mapErrors(e.getResult().getErrorsList(), maxIssues);
        if (!issues.isEmpty()) {
            return issues;
        }
        logFailure("PDF/A-1b syntax validation could not parse the document", e);
        return List.of(new PdfaIssue("NOT_VALIDATED", "PDF/A-1b validation could not parse the document"));
    }

    /**
     * Deduplicates and caps the errors while collecting them (T20): at most {@code maxIssues} distinct issues are
     * ever materialised, and the issues omitted after that are remembered only as a bounded set of keys to give
     * an exact count ("N additional issue(s) omitted") or, past {@link #MAX_TRACKED_OMITTED}, a lower bound
     * ("at least N ..."). Package-private (rather than {@code private}) specifically so it can be unit-tested in
     * isolation.
     */
    static List<PdfaIssue> mapErrors(List<ValidationResult.ValidationError> errors, int maxIssues) {
        Map<String, PdfaIssue> kept = new LinkedHashMap<>();
        Set<String> omitted = new HashSet<>();
        boolean omittedCountIsLowerBound = false;
        for (ValidationResult.ValidationError error : errors) {
            String code = error.getErrorCode();
            String message = error.getDetails() != null ? error.getDetails() : code;
            String key = code + "|" + message;
            if (kept.containsKey(key)) {
                continue;
            }
            if (kept.size() < maxIssues) {
                kept.put(key, new PdfaIssue(code, message));
            } else if (omitted.size() < MAX_TRACKED_OMITTED) {
                omitted.add(key);
            } else if (!omitted.contains(key)) {
                omittedCountIsLowerBound = true;
            }
        }
        List<PdfaIssue> issues = new ArrayList<>(kept.values());
        if (!omitted.isEmpty()) {
            issues.add(new PdfaIssue("TRUNCATED",
                    (omittedCountIsLowerBound ? "at least " : "") + omitted.size() + " additional issue(s) omitted"));
        }
        return issues;
    }

    private static PdfaReport notValidated(PdfaDeclaration declaration, String code, String message) {
        return new PdfaReport(declaration, PdfaValidationStatus.NOT_VALIDATED, List.of(new PdfaIssue(code, message)));
    }

    private static PdfaReport notValidated(PdfaDeclaration declaration, List<PdfaIssue> issues) {
        return new PdfaReport(declaration, PdfaValidationStatus.NOT_VALIDATED, issues);
    }
}
