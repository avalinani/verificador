package com.coam.pdfvalidator.application;

import com.coam.pdfvalidator.domain.model.AnalysisSection;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.DocumentHashes;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaIssue;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.SecurityInfo;
import com.coam.pdfvalidator.domain.model.SectionError;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy;
import com.coam.pdfvalidator.domain.port.CertificateChainValidator;
import com.coam.pdfvalidator.domain.port.HashCalculator;
import com.coam.pdfvalidator.domain.port.PdfDocumentReader;
import com.coam.pdfvalidator.domain.port.PdfaConformanceValidator;
import com.coam.pdfvalidator.domain.port.RevocationChecker;
import com.coam.pdfvalidator.domain.port.SignatureVerifier;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Orchestrates one full, single-pass PDF analysis by calling every domain
 * port in turn and assembling their results into one {@link
 * PdfAnalysisReport}. A plain class, constructor-injected with the domain
 * ports and a {@link Clock} (never {@code Instant.now()} directly, so
 * {@link #analyze} is deterministically testable); Spring wiring is added in
 * a later task.
 *
 * <h2>Order of operations</h2>
 * <ol>
 *   <li>{@link HashCalculator}: SHA-256/SHA-512 of the whole file.</li>
 *   <li>{@link PdfDocumentReader}: structure, security, and the raw XMP
 *       {@code pdfaid} declaration.</li>
 *   <li>{@link PdfaConformanceValidator}, combined with the declaration read
 *       above per the port's own documented contract (see {@link
 *       #analyzePdfa}).</li>
 *   <li>{@link SignatureVerifier}, then each extracted signature is enriched
 *       with chain trust ({@link CertificateChainValidator}) and, if
 *       requested, revocation ({@link RevocationChecker}) -- see {@link
 *       #enrich}.</li>
 * </ol>
 *
 * <h2>Encrypted or unreadable input: propagated, not caught</h2>
 * {@code readStructure}/{@code readSecurity}/{@code readPdfaDeclaration} can
 * throw the domain's {@code EncryptedPdfException} (a non-empty user
 * password) or {@code InvalidPdfException} (corrupt/non-PDF input). Both
 * propagate out of {@link #analyze} unchanged: there is no meaningful
 * partial {@link PdfAnalysisReport} to build for a document that could not
 * even be opened, and a future REST layer (T09) is expected to map both to
 * an HTTP 422 response. This is a deliberate choice, not an oversight -- see
 * the "Resilience" section below for the sections that instead degrade
 * gracefully.
 *
 * <h2>Resilience: one section's failure must not lose the rest of the report</h2>
 * Two sections are computed by adapters whose own contract already says
 * they should never throw for a single bad document (only the two
 * exceptions above escape them, and those are the whole-document failures
 * handled by propagation, above). As defense in depth against a bug in
 * either adapter, this use case additionally guards each of them
 * individually, so one adapter misbehaving cannot take down a report that
 * would otherwise be perfectly fine:
 * <ul>
 *   <li>{@link #analyzePdfa}: an unexpected {@link RuntimeException} from
 *       {@link PdfaConformanceValidator#validate} is reported as {@link
 *       PdfaValidationStatus#NOT_VALIDATED} with an explanatory issue,
 *       instead of aborting the whole analysis.</li>
 *   <li>{@link #verifySignatures}: an unexpected {@link RuntimeException}
 *       from {@link SignatureVerifier#verify} is reported as no signatures
 *       found (an empty list), instead of aborting the whole analysis.
 *       There is no per-signature granularity to fall back to here, since
 *       the failure happened before any signature could even be
 *       extracted.</li>
 *   <li>{@link #enrich}: chain validation and (optional) revocation checking
 *       for one signature are guarded together. A failure there leaves that
 *       one signature with its already-computed integrity/coverage/
 *       timestamp fields intact and its chain/revocation status at their
 *       {@code NOT_CHECKED}/{@code notChecked()} placeholders, with a note
 *       appended to {@link SignatureReport#anomaly()} -- every other
 *       signature, and the rest of the report, are unaffected.</li>
 * </ul>
 * {@link HashCalculator} is deliberately <b>not</b> guarded this way: hashing
 * a byte array cannot meaningfully fail for any of this project's own
 * implementations, and {@link PdfAnalysisReport} requires non-null hashes,
 * so there is no sensible placeholder to substitute if it somehow did.
 *
 * <h2>T08b: an empty result must never be silently indistinguishable from a
 * failure</h2>
 * Before T08b, {@link #verifySignatures}'s guard reported an unexpected
 * {@link SignatureVerifier} failure the exact same way as a legitimately
 * unsigned document: an empty {@code signatures} list either way. A caller
 * had no way to tell "this document has no signatures" apart from
 * "signature verification blew up and we don't actually know". Both guarded
 * sections above now additionally append a {@link SectionError} to {@link
 * PdfAnalysisReport#sectionErrors()} when their own {@code RuntimeException}
 * guard fires, so that ambiguity is always resolvable from the report
 * itself, in addition to (not instead of) the existing degrade-gracefully
 * behavior already described above.
 */
public final class AnalyzePdfUseCase {

    private static final System.Logger LOGGER = System.getLogger(AnalyzePdfUseCase.class.getName());

    private final HashCalculator hashCalculator;
    private final PdfDocumentReader pdfDocumentReader;
    private final SignatureVerifier signatureVerifier;
    private final CertificateChainValidator certificateChainValidator;
    private final PdfaConformanceValidator pdfaConformanceValidator;
    private final RevocationChecker revocationChecker;
    private final Clock clock;

    public AnalyzePdfUseCase(
            HashCalculator hashCalculator,
            PdfDocumentReader pdfDocumentReader,
            SignatureVerifier signatureVerifier,
            CertificateChainValidator certificateChainValidator,
            PdfaConformanceValidator pdfaConformanceValidator,
            RevocationChecker revocationChecker,
            Clock clock) {
        this.hashCalculator = Objects.requireNonNull(hashCalculator, "hashCalculator");
        this.pdfDocumentReader = Objects.requireNonNull(pdfDocumentReader, "pdfDocumentReader");
        this.signatureVerifier = Objects.requireNonNull(signatureVerifier, "signatureVerifier");
        this.certificateChainValidator = Objects.requireNonNull(certificateChainValidator, "certificateChainValidator");
        this.pdfaConformanceValidator = Objects.requireNonNull(pdfaConformanceValidator, "pdfaConformanceValidator");
        this.revocationChecker = Objects.requireNonNull(revocationChecker, "revocationChecker");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Runs the full analysis pipeline described in the class Javadoc.
     *
     * @param fileName the original file name, carried through unchanged for reporting
     * @param content  the whole PDF file's bytes
     * @param options  per-analysis options (currently just {@link AnalysisOptions#checkRevocation()})
     * @throws com.coam.pdfvalidator.domain.exception.EncryptedPdfException if the document requires a
     *                                                                      non-empty user password
     * @throws com.coam.pdfvalidator.domain.exception.InvalidPdfException   if the document is corrupt or not a PDF
     */
    public PdfAnalysisReport analyze(String fileName, byte[] content, AnalysisOptions options) {
        Objects.requireNonNull(fileName, "fileName");
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(options, "options");

        Instant analyzedAt = clock.instant();

        DocumentHashes hashes = hashCalculator.hash(content);

        // Propagates EncryptedPdfException/InvalidPdfException -- see class Javadoc.
        DocumentStructure structure = pdfDocumentReader.readStructure(content);
        SecurityInfo security = pdfDocumentReader.readSecurity(content);
        PdfaDeclaration declaration = pdfDocumentReader.readPdfaDeclaration(content);

        List<SectionError> sectionErrors = new ArrayList<>();
        PdfaReport pdfa = analyzePdfa(content, declaration, sectionErrors);
        List<SignatureReport> signatures = verifySignatures(content, options, sectionErrors);

        return new PdfAnalysisReport(
                fileName, content.length, hashes, structure, security, pdfa, signatures, analyzedAt, sectionErrors);
    }

    /**
     * Combines {@link PdfaConformanceValidator#validate} (always a formal
     * PDF/A-1b check, per its own contract) with the canonical XMP {@code
     * pdfaid} declaration read separately via {@link
     * PdfDocumentReader#readPdfaDeclaration}: a document declaring PDF/A-2
     * or PDF/A-3 is reported {@link PdfaValidationStatus#NOT_VALIDATED} with
     * an explanatory issue instead of the formal validator's own (almost
     * certainly {@code NON_COMPLIANT}, and misleading) 1b-specific result --
     * see {@code PdfaConformanceValidator}'s Javadoc and README section 2.8.
     * A document declaring PDF/A-1 (or no PDF/A part at all) uses the formal
     * validator's own status/issues unchanged.
     *
     * <p><b>Order of operations (T08b)</b>: the declaration is checked
     * <em>before</em> the formal validator is invoked, and the formal
     * validator is skipped entirely for a declared PDF/A-2/3 document -- its
     * (almost certainly {@code NON_COMPLIANT}) result would only be
     * discarded anyway, so there is no reason to pay for a full {@code
     * preflight} parse (documented elsewhere as a comparatively heavy
     * module) just to throw the result away. This also means a {@code
     * RuntimeException} from the formal validator can only affect a
     * PDF/A-1-or-undeclared document, since PDF/A-2/3 documents never reach
     * that call at all.
     */
    private PdfaReport analyzePdfa(byte[] content, PdfaDeclaration declaration, List<SectionError> sectionErrors) {
        if (declaration.isDeclared() && declaration.declaredPart().orElseThrow() != 1) {
            int declaredPart = declaration.declaredPart().orElseThrow();
            return new PdfaReport(declaration, PdfaValidationStatus.NOT_VALIDATED, List.of(new PdfaIssue(
                    "PDFA_PART_NOT_SUPPORTED",
                    "Document declares PDF/A-" + declaredPart
                            + "; only PDF/A-1b formal validation is supported, so this could not be validated")));
        }

        PdfaReport formal;
        try {
            formal = pdfaConformanceValidator.validate(content);
        } catch (RuntimeException e) {
            // T09b: the exception's own message must never reach the client
            // (it can carry internal detail unrelated to the PDF itself);
            // log it server-side and report a stable, non-sensitive message.
            LOGGER.log(System.Logger.Level.WARNING, "PDF/A-1b validation failed unexpectedly", e);
            String message = "PDF/A-1b validation failed unexpectedly";
            sectionErrors.add(new SectionError(AnalysisSection.PDFA, message));
            return new PdfaReport(declaration, PdfaValidationStatus.NOT_VALIDATED,
                    List.of(new PdfaIssue("NOT_VALIDATED", message)));
        }

        return new PdfaReport(declaration, formal.status(), formal.issues());
    }

    private List<SignatureReport> verifySignatures(
            byte[] content, AnalysisOptions options, List<SectionError> sectionErrors) {
        List<SignatureReport> extracted;
        try {
            extracted = signatureVerifier.verify(content);
        } catch (RuntimeException e) {
            LOGGER.log(System.Logger.Level.WARNING, "Signature verification failed unexpectedly", e);
            sectionErrors.add(new SectionError(
                    AnalysisSection.SIGNATURES, "signature verification failed unexpectedly"));
            return List.of();
        }

        List<SignatureReport> enriched = new ArrayList<>(extracted.size());
        for (SignatureReport signature : extracted) {
            enriched.add(enrich(signature, options));
        }
        // T11: the overall per-signature verdict is computed last, once every
        // signature's integrity/chain/revocation is known -- multi-signature
        // coverage needs to see all of them together (SignatureVerdictPolicy).
        return SignatureVerdictPolicy.evaluateAll(enriched, options.checkRevocation());
    }

    /**
     * Validates {@code signature}'s certificate chain at {@link
     * #resolveValidationTime}, and (if requested) checks revocation, then
     * returns the enriched report via {@link
     * SignatureReport#withChainAndRevocation}. Both steps are guarded
     * together: a failure leaves the signature's chain/revocation at their
     * {@code NOT_CHECKED}/{@code notChecked()} placeholders, with a note
     * appended to {@link SignatureReport#anomaly()} (merged with any
     * anomaly the {@code SignatureVerifier} itself already reported, e.g. an
     * unmappable certificate) -- see the class Javadoc's "Resilience"
     * section.
     */
    private SignatureReport enrich(SignatureReport signature, AnalysisOptions options) {
        try {
            Instant validationTime = resolveValidationTime(signature);
            ChainStatus chainStatus = certificateChainValidator.validate(signature.chain(), validationTime);
            RevocationStatus revocation = resolveRevocation(signature, chainStatus, validationTime, options);
            return signature.withChainAndRevocation(chainStatus, revocation);
        } catch (RuntimeException e) {
            // T09b: never surface the raw exception to the client -- log it
            // server-side, report a stable, non-sensitive anomaly note.
            LOGGER.log(System.Logger.Level.WARNING, "Chain/revocation enrichment failed unexpectedly", e);
            return withAppendedAnomaly(signature, "chain/revocation enrichment failed unexpectedly");
        }
    }

    /**
     * The instant chain validation (and expiry) is checked against: a valid
     * RFC 3161 signature timestamp's {@code genTime} when present and both
     * its imprint and TSA signature verify (an independently-verifiable
     * claim), otherwise the signature's own self-declared {@code
     * claimedSigningTime}, otherwise "now" ({@link Clock#instant()}) --
     * exactly the precedence documented on {@code
     * PkixCertificateChainValidator}'s Javadoc and README section 2.7.
     */
    private Instant resolveValidationTime(SignatureReport signature) {
        TimestampInfo timestamp = signature.timestamp();
        if (timestamp.isPresent() && timestamp.imprintValid() && timestamp.signatureValid()) {
            return timestamp.genTime();
        }
        return signature.claimedSigningTimeOptional().orElseGet(clock::instant);
    }

    /**
     * {@link RevocationStatus#notChecked()} when {@link
     * AnalysisOptions#checkRevocation()} is {@code false}.
     *
     * <h2>Trust gate (security decision, see the class Javadoc's "Resilience"
     * section for the general enrichment guard this sits inside)</h2>
     * Otherwise, revocation is checked <em>only when {@code chainStatus} is
     * already {@link ChainStatus#TRUSTED}</em> -- reported as {@code
     * NOT_CHECKED} with an explanatory detail for {@code UNTRUSTED_ROOT},
     * {@code INCOMPLETE_CHAIN}, {@code EXPIRED} or {@code NOT_CHECKED}
     * itself, even when the flag is on. This is not just an optimization:
     * the AIA/CDP URLs a revocation check would contact live inside
     * certificates a hostile CMS {@code SignedData} controls. For a
     * {@code TRUSTED} chain those certificates were written by a real,
     * trusted CA (the whole point of the chain being trusted), which closes
     * the main SSRF vector -- an uploader-crafted, self-signed "certificate"
     * declaring an internal OCSP URL never reaches a {@code TRUSTED}
     * verdict in the first place. The network-level SSRF guard ({@code
     * infrastructure.revocation.RevocationUrlGuard}/{@code
     * PinnedHttpClient}) is kept as defense in depth on top of this, not
     * instead of it.
     *
     * <p>When the gate passes, the signer certificate and its immediate
     * issuer are taken from {@link CertificateChainValidator#validatedPath}
     * -- the certificates PKIX itself used to reach that {@code TRUSTED}
     * verdict -- rather than from {@code signature.chain()} directly:
     * {@code chain()} is exactly what {@code SignatureVerifier} extracted
     * from the (attacker-controlled) CMS, which can carry extra or
     * unrelated certificates alongside a genuine path; {@code
     * validatedPath} narrows that down to only the certificates a trust
     * decision was actually made about.
     */
    private RevocationStatus resolveRevocation(
            SignatureReport signature, ChainStatus chainStatus, Instant validationTime, AnalysisOptions options) {
        if (!options.checkRevocation()) {
            return RevocationStatus.notChecked();
        }
        if (chainStatus != ChainStatus.TRUSTED) {
            return new RevocationStatus(
                    RevocationState.NOT_CHECKED, null, "revocation not checked: certificate chain is not trusted");
        }
        List<CertificateInfo> validatedPath = certificateChainValidator.validatedPath(signature.chain(), validationTime);
        if (validatedPath.isEmpty()) {
            // T10b: a TRUSTED chain reaching here with an empty validatedPath would
            // otherwise be indistinguishable from "revocation simply was not
            // requested" -- surface an explicit reason instead of silently skipping.
            return new RevocationStatus(
                    RevocationState.NOT_CHECKED, null, "validated certification path unavailable");
        }
        CertificateInfo certificate = validatedPath.get(0);
        CertificateInfo issuer = validatedPath.size() > 1 ? validatedPath.get(1) : null;
        return revocationChecker.check(certificate, issuer);
    }

    private static SignatureReport withAppendedAnomaly(SignatureReport signature, String note) {
        String anomaly = signature.anomalyOptional()
                .map(existing -> existing + "; " + note)
                .orElse(note);
        return new SignatureReport(
                signature.fieldName(), signature.subFilter(), signature.coverage(), signature.integrity(),
                signature.claimedSigningTime(), signature.timestamp(), signature.chain(),
                signature.chainStatus(), signature.revocation(), anomaly);
    }
}
