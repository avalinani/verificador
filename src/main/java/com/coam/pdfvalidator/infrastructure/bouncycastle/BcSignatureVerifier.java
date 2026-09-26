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
 * (T06/T10). Embedded timestamps are left as {@link TimestampInfo#absent()}
 * (T05).
 */
public final class BcSignatureVerifier implements SignatureVerifier {

    /** PAdES basic and CAdES detached signatures: the only subfilters this task verifies. */
    private static final Set<String> SUPPORTED_SUBFILTERS = Set.of(
            "adbe.pkcs7.detached", "ETSI.CAdES.detached");

    private final Provider bcProvider = new BouncyCastleProvider();

    @Override
    public List<SignatureReport> verify(byte[] pdf) {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            List<SignatureReport> reports = new ArrayList<>();
            for (PDSignatureField field : document.getSignatureFields()) {
                PDSignature signature = field.getSignature();
                if (signature == null) {
                    continue; // an unsigned signature field: nothing to report
                }
                reports.add(evaluate(pdf, field.getFullyQualifiedName(), signature));
            }
            return List.copyOf(reports);
        } catch (IOException e) {
            throw new InvalidPdfException("Failed to parse PDF for signature verification", e);
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
            return report(fieldName, subFilter, ByteRangeCoverage.unknown(pdf.length), IntegrityStatus.INVALID_SIGNATURE,
                    claimedSigningTime, List.of());
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
            return report(fieldName, subFilter, ByteRangeCoverage.unknown(pdf.length), IntegrityStatus.INVALID_SIGNATURE,
                    claimedSigningTime, List.of());
        }

        if (!isSupported(subFilter)) {
            return report(fieldName, subFilter, byteRange.coverage(), IntegrityStatus.UNSUPPORTED,
                    claimedSigningTime, List.of());
        }

        CmsSignatureVerification.Result cms =
                CmsSignatureVerification.verify(byteRange.signedBytes(), byteRange.cmsDer(), bcProvider);
        if (!cms.valid()) {
            return report(fieldName, subFilter, byteRange.coverage(), IntegrityStatus.INVALID_SIGNATURE,
                    claimedSigningTime, List.of());
        }

        IntegrityStatus integrity = byteRange.coverage().coversWholeDocument()
                ? IntegrityStatus.INTACT
                // The signature itself is valid for its own signed revision,
                // but bytes were appended afterwards (a later incremental
                // update, e.g. another signature): expected PDF behavior,
                // not itself a validation failure.
                : IntegrityStatus.MODIFIED_AFTER_SIGNING;

        List<CertificateInfo> chain = X509CertificateInfoMapper.toDomain(cms.certificateChain());

        return report(fieldName, subFilter, byteRange.coverage(), integrity, claimedSigningTime, chain);
    }

    private static boolean isSupported(String subFilter) {
        // Unknown subfilters, adbe.pkcs7.sha1, adbe.x509.rsa_sha1, and
        // ETSI.RFC3161 (a document timestamp signature, not a content
        // signature -- T05 handles those) are all reported as UNSUPPORTED
        // rather than crashing or being silently skipped.
        return subFilter != null && SUPPORTED_SUBFILTERS.contains(subFilter);
    }

    private static SignatureReport report(
            String fieldName, String subFilter, ByteRangeCoverage coverage, IntegrityStatus integrity,
            Instant claimedSigningTime, List<CertificateInfo> chain) {
        return new SignatureReport(
                fieldName,
                subFilter == null ? "" : subFilter,
                coverage,
                integrity,
                claimedSigningTime,
                TimestampInfo.absent(),
                chain,
                ChainStatus.NOT_CHECKED,
                RevocationStatus.notChecked());
    }

    private static Instant toInstant(Calendar signDate) {
        return signDate == null ? null : signDate.toInstant();
    }
}
