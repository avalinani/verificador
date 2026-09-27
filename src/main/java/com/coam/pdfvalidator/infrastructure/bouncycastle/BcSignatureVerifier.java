package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.ByteRangeCoverage;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import com.coam.pdfvalidator.domain.port.SignatureVerifier;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
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

    @Override
    public List<SignatureReport> verify(byte[] pdf) {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            List<SignatureReport> reports = new ArrayList<>();
            for (PDSignatureField field : document.getSignatureFields()) {
                SignatureReport report = evaluateField(pdf, field);
                if (report != null) {
                    reports.add(report);
                }
            }
            return List.copyOf(reports);
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to parse PDF for signature verification", e);
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
            return report(fieldName, subFilter, ByteRangeCoverage.unknown(pdf.length), IntegrityStatus.INVALID_SIGNATURE,
                    claimedSigningTime, TimestampInfo.absent(), List.of(), e.getMessage());
        }

        if (!isSupported(subFilter)) {
            return report(fieldName, subFilter, byteRange.coverage(), IntegrityStatus.UNSUPPORTED,
                    claimedSigningTime, TimestampInfo.absent(), List.of(),
                    "unsupported /SubFilter: " + (subFilter == null ? "(none)" : subFilter));
        }

        CmsSignatureVerification.Result cms =
                CmsSignatureVerification.verify(byteRange.signedBytes(), byteRange.cmsDer(), bcProvider);

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
