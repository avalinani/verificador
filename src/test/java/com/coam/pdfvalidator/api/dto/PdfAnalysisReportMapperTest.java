package com.coam.pdfvalidator.api.dto;

import com.coam.pdfvalidator.domain.model.AnalysisSection;
import com.coam.pdfvalidator.domain.model.Box;
import com.coam.pdfvalidator.domain.model.ByteRangeCoverage;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.DocumentHashes;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.Orientation;
import com.coam.pdfvalidator.domain.model.PageInfo;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaIssue;
import com.coam.pdfvalidator.domain.model.PdfaIssueCatalog;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.domain.model.Permission;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.Rotation;
import com.coam.pdfvalidator.domain.model.SecurityInfo;
import com.coam.pdfvalidator.domain.model.SectionError;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.SignatureVerdict;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Proves every field survives the domain-to-DTO mapping, and that a certificate's raw DER bytes never do. */
class PdfAnalysisReportMapperTest {

    private final PdfAnalysisReportMapper mapper = new PdfAnalysisReportMapper();

    @Test
    void mapsAFullReportFieldForField() throws Exception {
        byte[] encoded = {1, 2, 3, 4, 5};
        Instant notBefore = Instant.parse("2020-01-01T00:00:00Z");
        Instant notAfter = Instant.parse("2030-01-01T00:00:00Z");
        CertificateInfo certificate = new CertificateInfo(
                "CN=signer", "signer", "CN=issuer", "01", notBefore, notAfter, "SHA256withRSA",
                List.of("http://ocsp.example.org"), List.of("http://crl.example.org"), encoded);

        Box box = new Box(0, 0, 200, 100);
        PageInfo page = new PageInfo(1, 90, true, Rotation.DEG_90, box, box, Orientation.of(box, Rotation.DEG_90));
        DocumentStructure structure = new DocumentStructure("1.7", "1.7", 1, List.of(page), 2);
        SecurityInfo security = new SecurityInfo(true, EnumSet.of(Permission.PRINT, Permission.MODIFY));
        PdfaReport pdfa = new PdfaReport(
                new PdfaDeclaration(1, "B"), PdfaValidationStatus.COMPLIANT, List.of());

        Instant claimedSigningTime = Instant.parse("2026-01-01T00:00:00Z");
        Instant genTime = Instant.parse("2026-01-01T00:00:01Z");
        TimestampInfo timestamp = new TimestampInfo(genTime, "CN=tsa", true, true, certificate, "a note");
        SignatureReport signature = new SignatureReport(
                "Signature1", "adbe.pkcs7.detached", ByteRangeCoverage.of(0, 10, 10, 5, 15),
                IntegrityStatus.INTACT, claimedSigningTime, timestamp, List.of(certificate),
                ChainStatus.TRUSTED, new RevocationStatus(RevocationState.GOOD, "http://ocsp.example.org", null),
                "an anomaly").withVerdict(SignatureVerdict.VALID, List.of());

        Instant analyzedAt = Instant.parse("2026-09-27T10:00:00Z");
        PdfAnalysisReport report = new PdfAnalysisReport(
                "document.pdf", 1024, new DocumentHashes("a".repeat(64), "b".repeat(128)), structure, security,
                pdfa, List.of(signature), analyzedAt,
                List.of(new SectionError(AnalysisSection.PDFA, "boom")));

        PdfAnalysisReportDto dto = mapper.toDto(report);

        assertThat(dto.fileName()).isEqualTo("document.pdf");
        assertThat(dto.sizeBytes()).isEqualTo(1024);
        assertThat(dto.hashes().sha256()).isEqualTo("a".repeat(64));
        assertThat(dto.hashes().sha512()).isEqualTo("b".repeat(128));
        assertThat(dto.analyzedAt()).isEqualTo(analyzedAt);

        assertThat(dto.structure().headerVersion()).isEqualTo("1.7");
        assertThat(dto.structure().pageCount()).isEqualTo(1);
        assertThat(dto.structure().revisionCount()).isEqualTo(2);
        assertThat(dto.structure().pages()).hasSize(1);
        assertThat(dto.structure().pages().get(0).rotation()).isEqualTo("DEG_90");
        assertThat(dto.structure().pages().get(0).rawRotation()).isEqualTo(90);
        assertThat(dto.structure().pages().get(0).rotationValid()).isTrue();
        assertThat(dto.structure().pages().get(0).orientation()).isEqualTo(Orientation.of(box, Rotation.DEG_90).name());
        assertThat(dto.structure().pages().get(0).mediaBox().width()).isEqualTo(200f);
        assertThat(dto.structure().pages().get(0).mediaBox().height()).isEqualTo(100f);

        assertThat(dto.security().encrypted()).isTrue();
        assertThat(dto.security().permissions()).containsExactlyInAnyOrder("PRINT", "MODIFY");

        assertThat(dto.pdfa().status()).isEqualTo("COMPLIANT");
        assertThat(dto.pdfa().declaration().declared()).isTrue();
        assertThat(dto.pdfa().declaration().part()).isEqualTo(1);
        assertThat(dto.pdfa().declaration().conformance()).isEqualTo("B");

        assertThat(dto.signatures()).hasSize(1);
        SignatureReportDto signatureDto = dto.signatures().get(0);
        assertThat(signatureDto.fieldName()).isEqualTo("Signature1");
        assertThat(signatureDto.integrity()).isEqualTo("INTACT");
        assertThat(signatureDto.chainStatus()).isEqualTo("TRUSTED");
        assertThat(signatureDto.anomaly()).isEqualTo("an anomaly");
        assertThat(signatureDto.claimedSigningTime()).isEqualTo(claimedSigningTime);
        assertThat(signatureDto.coverage().ranges()).containsExactly(0L, 10L, 10L, 5L);
        assertThat(signatureDto.coverage().coversWholeDocument()).isTrue();
        assertThat(signatureDto.revocation().state()).isEqualTo("GOOD");
        assertThat(signatureDto.revocation().source()).isEqualTo("http://ocsp.example.org");

        assertThat(signatureDto.timestamp().present()).isTrue();
        assertThat(signatureDto.timestamp().genTime()).isEqualTo(genTime);
        assertThat(signatureDto.timestamp().tsaName()).isEqualTo("CN=tsa");
        assertThat(signatureDto.timestamp().imprintValid()).isTrue();
        assertThat(signatureDto.timestamp().signatureValid()).isTrue();
        assertThat(signatureDto.timestamp().note()).isEqualTo("a note");

        CertificateInfoDto signerDto = signatureDto.chain().get(0);
        assertThat(signerDto.subject()).isEqualTo("CN=signer");
        assertThat(signerDto.commonName()).isEqualTo("signer");
        assertThat(signerDto.issuer()).isEqualTo("CN=issuer");
        assertThat(signerDto.serialNumberHex()).isEqualTo("01");
        assertThat(signerDto.notBefore()).isEqualTo(notBefore);
        assertThat(signerDto.notAfter()).isEqualTo(notAfter);
        assertThat(signerDto.ocspUrls()).containsExactly("http://ocsp.example.org");
        assertThat(signerDto.crlUrls()).containsExactly("http://crl.example.org");
        assertThat(signerDto.sha256Fingerprint()).isEqualTo(sha256Hex(encoded));

        CertificateInfoDto tsaCertificateDto = signatureDto.timestamp().tsaCertificate();
        assertThat(tsaCertificateDto.sha256Fingerprint()).isEqualTo(sha256Hex(encoded));

        assertThat(dto.sectionErrors()).hasSize(1);
        assertThat(dto.sectionErrors().get(0).section()).isEqualTo("PDFA");
        assertThat(dto.sectionErrors().get(0).message()).isEqualTo("boom");

        assertThat(signatureDto.verdict()).isEqualTo("VALID");
        assertThat(signatureDto.verdictReasons()).isEmpty();
        assertThat(dto.overallVerdict()).isEqualTo("VALID");
        assertThat(dto.modifiedAfterLastSignature()).isFalse();
    }

    @Test
    void anUnsignedDocumentMapsToTheNoSignaturesOverallVerdict() {
        DocumentStructure structure = new DocumentStructure("1.7", null, 0, List.of(), 1);
        SecurityInfo security = new SecurityInfo(false, EnumSet.noneOf(Permission.class));
        PdfaReport pdfa = new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of());
        PdfAnalysisReport report = new PdfAnalysisReport(
                "unsigned.pdf", 10, new DocumentHashes("a".repeat(64), "b".repeat(128)), structure, security, pdfa,
                List.of(), Instant.EPOCH, List.of());

        PdfAnalysisReportDto dto = mapper.toDto(report);

        assertThat(dto.overallVerdict()).isEqualTo("NO_SIGNATURES");
        assertThat(dto.modifiedAfterLastSignature()).isFalse();
        assertThat(dto.signatures()).isEmpty();
    }

    @Test
    void neverExposesTheCertificatesRawDerBytesAsAField() {
        // A structural guarantee, not just an absence-of-assertion: CertificateInfoDto
        // has no component that could carry the raw encoded bytes at all.
        assertThat(CertificateInfoDto.class.getRecordComponents())
                .extracting(java.lang.reflect.RecordComponent::getType)
                .noneMatch(type -> type.equals(byte[].class));
    }

    @Test
    void aPdfaIssueWithAKnownPreflightCodeAlsoGetsItsSpanishTranslation() {
        // 7.1 = ERROR_METADATA_FORMAT (PdfaIssueCatalogTest, T11g): a real
        // code PDFBox's own preflight reports, e.g. "Metadata is not a stream".
        DocumentStructure structure = new DocumentStructure("1.7", null, 0, List.of(), 1);
        SecurityInfo security = new SecurityInfo(false, EnumSet.noneOf(Permission.class));
        PdfaReport pdfa = new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of(
                new PdfaIssue("7.1", "Metadata is not a stream")));
        PdfAnalysisReport report = new PdfAnalysisReport(
                "unsigned.pdf", 10, new DocumentHashes("a".repeat(64), "b".repeat(128)), structure, security, pdfa,
                List.of(), Instant.EPOCH, List.of());

        PdfAnalysisReportDto dto = mapper.toDto(report);

        PdfaIssueDto issueDto = dto.pdfa().issues().get(0);
        assertThat(issueDto.code()).isEqualTo("7.1");
        assertThat(issueDto.message()).isEqualTo("Metadata is not a stream");
        assertThat(issueDto.messageEs()).isEqualTo(PdfaIssueCatalog.spanishMessage("7.1").orElseThrow());
    }

    @Test
    void absentTimestampMapsToPresentFalseWithNoCertificate() {
        DocumentStructure structure = new DocumentStructure("1.7", null, 0, List.of(), 1);
        SecurityInfo security = new SecurityInfo(false, EnumSet.noneOf(Permission.class));
        PdfaReport pdfa = new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of(
                new PdfaIssue("CODE", "message")));
        SignatureReport signature = new SignatureReport(
                "Signature1", "adbe.pkcs7.detached", ByteRangeCoverage.of(0, 10, 10, 5, 15),
                IntegrityStatus.UNSUPPORTED, null, TimestampInfo.absent(), List.of(),
                ChainStatus.NOT_CHECKED, RevocationStatus.notChecked(), null);
        PdfAnalysisReport report = new PdfAnalysisReport(
                "t.pdf", 10, new DocumentHashes("a".repeat(64), "b".repeat(128)), structure, security, pdfa,
                List.of(signature), Instant.EPOCH, List.of());

        PdfAnalysisReportDto dto = mapper.toDto(report);

        assertThat(dto.signatures().get(0).timestamp().present()).isFalse();
        assertThat(dto.signatures().get(0).timestamp().tsaCertificate()).isNull();
        assertThat(dto.signatures().get(0).claimedSigningTime()).isNull();
        assertThat(dto.signatures().get(0).anomaly()).isNull();
        assertThat(dto.pdfa().declaration().declared()).isFalse();
        assertThat(dto.pdfa().issues()).hasSize(1);
        // "CODE" is not a real PDFBox preflight code (T11g): the UI must show
        // only the original English message for it, never a fabricated translation.
        assertThat(dto.pdfa().issues().get(0).messageEs()).isNull();
        assertThat(dto.sectionErrors()).isEmpty();
        // Built with the pre-T11 10-arg SignatureReport constructor: verdict
        // defaults to its safe NOT_ADMITTED placeholder (never computed here).
        assertThat(dto.signatures().get(0).verdict()).isEqualTo("NOT_ADMITTED");
        assertThat(dto.signatures().get(0).verdictReasons()).isEmpty();
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(bytes));
    }
}
