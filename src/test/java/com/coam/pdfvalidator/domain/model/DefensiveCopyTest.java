package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Proves every collection-holding domain record copies its input rather than
 * aliasing it, so a caller mutating the list/set it passed in cannot corrupt
 * an already-built (supposedly immutable) domain object.
 */
class DefensiveCopyTest {

    @Test
    void documentStructureCopiesItsPagesList() {
        Box box = new Box(0, 0, 100, 100);
        PageInfo page = new PageInfo(1, 0, true, Rotation.DEG_0, box, box, Orientation.SQUARE);
        List<PageInfo> mutablePages = new ArrayList<>(List.of(page));

        DocumentStructure structure = new DocumentStructure("1.7", null, 1, mutablePages, 1);
        mutablePages.add(page);

        assertThat(structure.pages()).hasSize(1);
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> structure.pages().add(page));
    }

    @Test
    void securityInfoCopiesItsPermissionsSet() {
        var mutablePermissions = EnumSet.of(Permission.PRINT);

        SecurityInfo security = new SecurityInfo(true, mutablePermissions);
        mutablePermissions.add(Permission.MODIFY);

        assertThat(security.permissions()).containsExactly(Permission.PRINT);
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> security.permissions().add(Permission.ASSEMBLE));
    }

    @Test
    void pdfaReportCopiesItsIssuesList() {
        List<PdfaIssue> mutableIssues = new ArrayList<>(List.of(new PdfaIssue("E001", "bad object")));

        PdfaReport report = new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, mutableIssues);
        mutableIssues.add(new PdfaIssue("E002", "another issue"));

        assertThat(report.issues()).hasSize(1);
    }

    @Test
    void signatureReportCopiesItsCertificateChain() {
        List<CertificateInfo> mutableChain = new ArrayList<>();

        SignatureReport report = new SignatureReport(
                "Signature1",
                "ETSI.CAdES.detached",
                ByteRangeCoverage.of(0, 10, 20, 10, 30),
                IntegrityStatus.INTACT,
                null,
                TimestampInfo.absent(),
                mutableChain,
                ChainStatus.NOT_CHECKED,
                RevocationStatus.notChecked(),
                null);

        mutableChain.add(null);

        assertThat(report.chain()).isEmpty();
    }

    @Test
    void signatureReportCopiesItsVerdictReasonsList() {
        List<CertificateInfo> chain = List.of();
        SignatureReport base = new SignatureReport(
                "Signature1", "ETSI.CAdES.detached", ByteRangeCoverage.of(0, 10, 20, 10, 30),
                IntegrityStatus.INTACT, null, TimestampInfo.absent(), chain,
                ChainStatus.NOT_CHECKED, RevocationStatus.notChecked(), null);
        List<String> mutableReasons = new ArrayList<>(List.of("REASON_ONE"));

        SignatureReport report = base.withVerdict(SignatureVerdict.VALID, mutableReasons);
        mutableReasons.add("REASON_TWO");

        assertThat(report.verdictReasons()).containsExactly("REASON_ONE");
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> report.verdictReasons().add("REASON_THREE"));
    }

    @Test
    void pdfAnalysisReportCopiesItsSignaturesList() {
        List<SignatureReport> mutableSignatures = new ArrayList<>();

        PdfAnalysisReport analysis = new PdfAnalysisReport(
                "document.pdf",
                1024,
                new DocumentHashes("a".repeat(64), "b".repeat(128)),
                new DocumentStructure("1.7", null, 0, List.of(), 1),
                new SecurityInfo(false, java.util.Set.of()),
                new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of()),
                mutableSignatures,
                java.time.Instant.now(),
                List.of());

        mutableSignatures.add(null);

        assertThat(analysis.signatures()).isEmpty();
    }

    @Test
    void pdfAnalysisReportCopiesItsSectionErrorsList() {
        List<SectionError> mutableSectionErrors = new ArrayList<>();

        PdfAnalysisReport analysis = new PdfAnalysisReport(
                "document.pdf",
                1024,
                new DocumentHashes("a".repeat(64), "b".repeat(128)),
                new DocumentStructure("1.7", null, 0, List.of(), 1),
                new SecurityInfo(false, java.util.Set.of()),
                new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.NOT_VALIDATED, List.of()),
                List.of(),
                java.time.Instant.now(),
                mutableSectionErrors);

        mutableSectionErrors.add(new SectionError(AnalysisSection.PDFA, "irrelevant"));

        assertThat(analysis.sectionErrors()).isEmpty();
    }
}
