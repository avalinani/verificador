package com.coam.pdfvalidator.api.dto;

import com.coam.pdfvalidator.domain.model.Box;
import com.coam.pdfvalidator.domain.model.ByteRangeCoverage;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.DocumentHashes;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.PageInfo;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaIssue;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.Permission;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.SecurityInfo;
import com.coam.pdfvalidator.domain.model.SectionError;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.TimestampInfo;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Maps the domain's {@link PdfAnalysisReport} (and everything it carries) to
 * its stable, JSON-friendly {@link PdfAnalysisReportDto}, without ever
 * exposing a domain or third-party library type -- or a certificate's raw
 * DER encoding -- on the wire (see {@link #sha256Fingerprint(byte[])}).
 */
@Component
public class PdfAnalysisReportMapper {

    private static final HexFormat HEX = HexFormat.of();

    public PdfAnalysisReportDto toDto(PdfAnalysisReport report) {
        return new PdfAnalysisReportDto(
                report.fileName(),
                report.sizeBytes(),
                toDto(report.hashes()),
                toDto(report.structure()),
                toDto(report.security()),
                toDto(report.pdfa()),
                report.signatures().stream().map(this::toDto).collect(Collectors.toList()),
                report.analyzedAt(),
                report.sectionErrors().stream().map(PdfAnalysisReportMapper::toDto).collect(Collectors.toList()),
                report.overallVerdict().name(),
                report.modifiedAfterLastSignature());
    }

    private static DocumentHashesDto toDto(DocumentHashes hashes) {
        return new DocumentHashesDto(hashes.sha256(), hashes.sha512());
    }

    private static DocumentStructureDto toDto(DocumentStructure structure) {
        List<PageInfoDto> pages = structure.pages().stream()
                .map(PdfAnalysisReportMapper::toDto)
                .collect(Collectors.toList());
        return new DocumentStructureDto(
                structure.headerVersion(), structure.catalogVersion(), structure.pageCount(), pages,
                structure.revisionCount());
    }

    private static PageInfoDto toDto(PageInfo page) {
        return new PageInfoDto(
                page.number(), page.rawRotation(), page.rotationValid(), page.rotation().name(),
                toDto(page.mediaBox()), toDto(page.cropBox()), page.orientation().name());
    }

    private static BoxDto toDto(Box box) {
        return new BoxDto(box.llx(), box.lly(), box.urx(), box.ury(), box.width(), box.height());
    }

    private static SecurityInfoDto toDto(SecurityInfo security) {
        return new SecurityInfoDto(
                security.encrypted(),
                security.permissions().stream().map(Permission::name).collect(Collectors.toSet()));
    }

    private static PdfaReportDto toDto(PdfaReport pdfa) {
        List<PdfaIssueDto> issues = pdfa.issues().stream()
                .map(PdfAnalysisReportMapper::toDto)
                .collect(Collectors.toList());
        return new PdfaReportDto(toDto(pdfa.declaration()), pdfa.status().name(), issues);
    }

    private static PdfaDeclarationDto toDto(PdfaDeclaration declaration) {
        return new PdfaDeclarationDto(
                declaration.part(), declaration.conformance(), declaration.isDeclared());
    }

    private static PdfaIssueDto toDto(PdfaIssue issue) {
        return new PdfaIssueDto(issue.code(), issue.message());
    }

    private static SectionErrorDto toDto(SectionError error) {
        return new SectionErrorDto(error.section().name(), error.message());
    }

    private SignatureReportDto toDto(SignatureReport signature) {
        List<CertificateInfoDto> chain = signature.chain().stream()
                .map(this::toDto)
                .collect(Collectors.toList());
        return new SignatureReportDto(
                signature.fieldName(),
                signature.subFilter(),
                toDto(signature.coverage()),
                signature.integrity().name(),
                signature.claimedSigningTime(),
                toDto(signature.timestamp()),
                chain,
                signature.chainStatus().name(),
                toDto(signature.revocation()),
                signature.anomaly(),
                signature.verdict().name(),
                signature.verdictReasons());
    }

    private static ByteRangeCoverageDto toDto(ByteRangeCoverage coverage) {
        return new ByteRangeCoverageDto(coverage.ranges(), coverage.fileLength(), coverage.coversWholeDocument());
    }

    private TimestampInfoDto toDto(TimestampInfo timestamp) {
        CertificateInfoDto tsaCertificate = timestamp.tsaCertificate() != null ? toDto(timestamp.tsaCertificate()) : null;
        return new TimestampInfoDto(
                timestamp.genTime(), timestamp.tsaName(), timestamp.isPresent(), timestamp.imprintValid(),
                timestamp.signatureValid(), tsaCertificate, timestamp.note());
    }

    private CertificateInfoDto toDto(CertificateInfo certificate) {
        return new CertificateInfoDto(
                certificate.subject(), certificate.issuer(), certificate.serialNumberHex(), certificate.notBefore(),
                certificate.notAfter(), certificate.signatureAlgorithm(), certificate.ocspUrls(),
                certificate.crlUrls(), sha256Fingerprint(certificate.encoded()));
    }

    private static RevocationStatusDto toDto(RevocationStatus revocation) {
        return new RevocationStatusDto(revocation.state().name(), revocation.source(), revocation.detail());
    }

    /**
     * A SHA-256 fingerprint of the certificate's DER encoding, as lowercase
     * hex -- a stable, compact identifier a client can compare or look up,
     * without this API ever exposing the certificate's raw encoded bytes.
     */
    private static String sha256Fingerprint(byte[] encoded) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HEX.formatHex(digest.digest(encoded));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by every JVM implementation; unreachable in practice.
            throw new IllegalStateException("JVM does not support SHA-256", e);
        }
    }
}
