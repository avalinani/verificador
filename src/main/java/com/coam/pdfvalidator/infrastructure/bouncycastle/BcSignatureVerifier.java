package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.ByteRangeCoverage;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.SignatureExtraction;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import com.coam.pdfvalidator.domain.port.SignatureVerifier;
import com.coam.pdfvalidator.domain.port.TrustedCertificateSource;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Provider;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Set;

/**
 * {@link SignatureVerifier} adapter built on Apache PDFBox 3 (for signature
 * dictionary access) and Bouncy Castle 1.86 (for CMS/PKCS#7 parsing and
 * verification). Never lets a PDFBox or Bouncy Castle type escape into a
 * caller, and never throws for a single hostile/malformed signature -- only
 * a whole-document parsing failure raises {@link InvalidPdfException}.
 *
 * <p>Uses a private {@link BouncyCastleProvider} instance passed explicitly
 * to each builder, rather than registering it globally via {@link
 * java.security.Security#addProvider}: this adapter does not mutate global
 * JVM state.
 *
 * <p>Chain trust and revocation are left as {@link ChainStatus#NOT_CHECKED}
 * / {@link RevocationStatus#notChecked()} placeholders, per {@link
 * SignatureVerifier}'s Javadoc: they are the use case's responsibility
 * (T06/T10).
 */
public final class BcSignatureVerifier implements SignatureVerifier {

    private static final System.Logger LOG = System.getLogger(BcSignatureVerifier.class.getName());

    /** PAdES basic and CAdES detached signatures: the only subfilters this task verifies. */
    private static final Set<String> SUPPORTED_SUBFILTERS = Set.of(
            "adbe.pkcs7.detached", "ETSI.CAdES.detached");

    private final Provider bcProvider = new BouncyCastleProvider();
    private final SignatureLimits limits;
    private final TrustedCertificateSource trustedCertificates;

    public BcSignatureVerifier() {
        this(SignatureLimits.DEFAULT);
    }

    public BcSignatureVerifier(SignatureLimits limits) {
        this(limits, TrustedCertificateSource.none());
    }

    /**
     * @param trustedCertificates where a timestamp authority certificate that the RFC 3161 token does not carry
     *                            may additionally be looked up (T26a); a lookup source only, never a trust decision
     */
    public BcSignatureVerifier(SignatureLimits limits, TrustedCertificateSource trustedCertificates) {
        this.limits = java.util.Objects.requireNonNull(limits, "limits");
        this.trustedCertificates = java.util.Objects.requireNonNull(trustedCertificates, "trustedCertificates");
    }

    @Override
    public List<SignatureReport> verify(byte[] pdf) {
        return extract(pdf).signatures();
    }

    /**
     * Analyses at most {@link SignatureLimits#maxSignatureFields()} signature fields (T20): the form's field
     * tree is walked lazily instead of materialising every signature field first, and each further field that
     * does hold a signature is only counted, never analysed. The caller must treat a positive {@code
     * skippedFields} as an incomplete analysis.
     */
    @Override
    public SignatureExtraction extract(byte[] pdf) {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            List<SignatureReport> reports = new ArrayList<>();
            int skipped = 0;
            int analysed = 0;
            PDAcroForm acroForm = document.getDocumentCatalog().getAcroForm(null);
            if (acroForm != null) {
                for (PDField field : acroForm.getFieldTree()) {
                    if (!(field instanceof PDSignatureField signatureField)) {
                        continue;
                    }
                    if (analysed < limits.maxSignatureFields()) {
                        SignatureReport report = evaluateField(pdf, signatureField);
                        if (report != null) {
                            reports.add(report);
                            analysed++;
                        }
                    } else if (holdsASignature(signatureField)) {
                        skipped++;
                    }
                }
            }
            return new SignatureExtraction(reports, skipped);
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to parse PDF for signature verification", e);
        }
    }

    /** Whether a field beyond the cap has something to hide; a field that cannot even be read is assumed to. */
    private static boolean holdsASignature(PDSignatureField field) {
        try {
            return field.getSignature() != null;
        } catch (RuntimeException e) {
            return true;
        }
    }

    /**
     * Evaluates one signature field, guarding the <em>entire</em> per-field
     * evaluation -- including reading the {@link PDSignature} and its field
     * name back from PDFBox -- against an escaping {@link RuntimeException}.
     * A previous version only guarded {@link #evaluateUnsafe}, leaving a
     * runtime exception thrown while merely reading the field (e.g. {@link
     * PDSignatureField#getSignature()} or {@link
     * PDSignatureField#getFullyQualifiedName()}) free to abort the whole
     * document's analysis; a single hostile or malformed field must never
     * do that.
     */
    SignatureReport evaluateField(byte[] pdf, PDSignatureField field) {
        try {
            PDSignature signature = field.getSignature();
            if (signature == null) {
                return null; // an unsigned signature field: nothing to report
            }
            return evaluate(pdf, field.getFullyQualifiedName(), signature);
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to read a signature field", e);
            return report(unknownFieldName(field), "", ByteRangeCoverage.unknown(pdf.length),
                    IntegrityStatus.INVALID_SIGNATURE, null, TimestampInfo.absent(), List.of(),
                    "signature field could not be read");
        }
    }

    private static String unknownFieldName(PDSignatureField field) {
        try {
            String name = field.getFullyQualifiedName();
            return name != null ? name : "unknown";
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    /**
     * Evaluates a single signature dictionary. Deliberately catches every
     * {@link RuntimeException} in addition to the specific cases already
     * handled below: a single hostile or malformed signature must never
     * abort the analysis of the whole document.
     */
    private SignatureReport evaluate(byte[] pdf, String fieldName, PDSignature signature) {
        String subFilter = signature.getSubFilter();
        Instant claimedSigningTime = toInstant(signature.getSignDate());
        try {
            return evaluateUnsafe(pdf, fieldName, subFilter, claimedSigningTime, signature);
        } catch (IOException | RuntimeException e) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to evaluate a signature", e);
            return report(fieldName, subFilter, ByteRangeCoverage.unknown(pdf.length), IntegrityStatus.INVALID_SIGNATURE,
                    claimedSigningTime, TimestampInfo.absent(), List.of(), "signature could not be evaluated");
        }
    }

    private SignatureReport evaluateUnsafe(
            byte[] pdf, String fieldName, String subFilter, Instant claimedSigningTime, PDSignature signature)
            throws IOException {
        SignatureByteRange byteRange;
        try {
            byteRange = SignatureByteRange.parse(pdf, signature);
        } catch (IllegalArgumentException e) {
            // Structurally broken /ByteRange (or a /ByteRange <-> /Contents
            // mismatch): reject without ever attempting to parse the CMS.
            // The exception's own message already names the structural
            // problem (e.g. "ByteRange gap is out of bounds: ..."), and is
            // safe to surface: it describes the file's own structure, not
            // any sensitive data.
            String reason = byteRangeFailureReason(e);
            return report(fieldName, subFilter, ByteRangeCoverage.unknown(pdf.length), IntegrityStatus.INVALID_SIGNATURE,
                    claimedSigningTime, TimestampInfo.absent(), List.of(), reason);
        }

        if (!isSupported(subFilter)) {
            return report(fieldName, subFilter, byteRange.coverage(), IntegrityStatus.UNSUPPORTED,
                    claimedSigningTime, TimestampInfo.absent(), List.of(),
                    "unsupported /SubFilter: " + (subFilter == null ? "(none)" : subFilter));
        }

        CmsSignatureVerification.Result cms =
                CmsSignatureVerification.verify(byteRange.signedBytes(), byteRange.cmsDer(), bcProvider, limits, trustedCertificates);

        // A CMS that parsed must not be reported with an empty chain merely
        // because verification failed, or because one certificate's data
        // could not be re-encoded: keep whatever certificates could be
        // mapped (even when cms.valid() is false) and surface the rest as an
        // anomaly note instead of silently dropping them.
        X509CertificateInfoMapper.MappingResult mapped =
                X509CertificateInfoMapper.toDomainResilient(cms.certificateChain());
        String mappingAnomaly = mapped.failedCount() > 0
                ? "Failed to map " + mapped.failedCount() + " of " + cms.certificateChain().size()
                        + " certificate(s) extracted from the signature; the reported chain may be partial"
                : null;

        if (!cms.valid()) {
            String anomaly = combineNotes(combineNotes(cms.reason(), cms.anomaly()), mappingAnomaly);
            return report(fieldName, subFilter, byteRange.coverage(), IntegrityStatus.INVALID_SIGNATURE,
                    claimedSigningTime, cms.timestamp(), mapped.certificates(), anomaly);
        }

        IntegrityStatus integrity = byteRange.coverage().coversWholeDocument()
                ? IntegrityStatus.INTACT
                // The signature itself is valid for its own signed revision,
                // but bytes were appended afterwards (a later incremental
                // update, e.g. another signature): expected PDF behavior,
                // not itself a validation failure.
                : IntegrityStatus.MODIFIED_AFTER_SIGNING;

        String anomaly = combineNotes(cms.anomaly(), mappingAnomaly);

        return report(fieldName, subFilter, byteRange.coverage(), integrity, claimedSigningTime,
                cms.timestamp(), mapped.certificates(), anomaly);
    }

    /**
     * The anomaly reason for a structurally broken {@code /ByteRange}:
     * {@code e}'s own message when present, or a fixed, still-non-sensitive
     * fallback on the (currently unreachable through any real PDF -- every
     * throw site in {@code SignatureByteRange}/{@code ByteRangeCoverage}
     * carries an explicit message -- but not guaranteed to stay that way)
     * chance that the exception itself carries no message: an anomaly must
     * always be a stable, non-null reason. Package-private (T09d follow-up)
     * specifically so this otherwise-unreachable branch can be unit-tested
     * directly, without needing to construct a PDF that can actually drive
     * it.
     */
    static String byteRangeFailureReason(IllegalArgumentException e) {
        return e.getMessage() != null ? e.getMessage() : "invalid /ByteRange";
    }

    private static String combineNotes(String a, String b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a + "; " + b;
    }

    private static boolean isSupported(String subFilter) {
        // Unknown subfilters, adbe.pkcs7.sha1, adbe.x509.rsa_sha1, and
        // ETSI.RFC3161 (a document timestamp signature, not a content
        // signature -- kept UNSUPPORTED, see the README's T05 section for
        // why) are all reported as UNSUPPORTED rather than crashing or
        // being silently skipped.
        return subFilter != null && SUPPORTED_SUBFILTERS.contains(subFilter);
    }

    private static SignatureReport report(
            String fieldName, String subFilter, ByteRangeCoverage coverage, IntegrityStatus integrity,
            Instant claimedSigningTime, TimestampInfo timestamp, List<CertificateInfo> chain, String anomaly) {
        return new SignatureReport(
                fieldName,
                subFilter == null ? "" : subFilter,
                coverage,
                integrity,
                claimedSigningTime,
                timestamp,
                chain,
                ChainStatus.NOT_CHECKED,
                RevocationStatus.notChecked(),
                anomaly);
    }

    private static Instant toInstant(Calendar signDate) {
        return signDate == null ? null : signDate.toInstant();
    }
}
