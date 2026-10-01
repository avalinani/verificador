package com.coam.pdfvalidator.api.dto;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The response DTOs are records, which only make the references final: without a defensive copy a
 * caller keeps a handle on the collection inside the DTO (SpotBugs EI_EXPOSE_REP/REP2). Each DTO
 * must therefore snapshot its collections at construction and expose them read-only.
 */
class DtoDefensiveCopyTest {

    @Test
    void byteRangeCoverageSnapshotsItsRanges() {
        List<Long> source = new ArrayList<>(List.of(0L, 10L, 20L, 5L));
        ByteRangeCoverageDto dto = new ByteRangeCoverageDto(source, 25L, true);

        source.add(99L);

        assertThat(dto.ranges()).containsExactly(0L, 10L, 20L, 5L);
        assertThatThrownBy(() -> dto.ranges().add(1L)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void certificateInfoSnapshotsItsUrlLists() {
        List<String> ocsp = new ArrayList<>(List.of("http://ocsp.example"));
        List<String> crl = new ArrayList<>(List.of("http://crl.example"));
        CertificateInfoDto dto = new CertificateInfoDto(
                "s", "cn", "i", "01", null, null, "alg", ocsp, crl, "fp");

        ocsp.clear();
        crl.clear();

        assertThat(dto.ocspUrls()).containsExactly("http://ocsp.example");
        assertThat(dto.crlUrls()).containsExactly("http://crl.example");
        assertThatThrownBy(() -> dto.ocspUrls().add("x")).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> dto.crlUrls().add("x")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void documentStructureSnapshotsItsPages() {
        List<PageInfoDto> pages = new ArrayList<>();
        DocumentStructureDto dto = new DocumentStructureDto("1.7", null, 0, pages, 1, false, false);

        pages.add(null);

        assertThat(dto.pages()).isEmpty();
        assertThatThrownBy(() -> dto.pages().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void securityInfoSnapshotsItsPermissions() {
        Set<String> permissions = new HashSet<>(Set.of("PRINT"));
        SecurityInfoDto dto = new SecurityInfoDto(true, permissions);

        permissions.add("MODIFY");

        assertThat(dto.permissions()).containsExactly("PRINT");
        assertThatThrownBy(() -> dto.permissions().add("x")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void pdfaReportSnapshotsItsIssues() {
        List<PdfaIssueDto> issues = new ArrayList<>();
        PdfaReportDto dto = new PdfaReportDto(null, "COMPLIANT", issues);

        issues.add(null);

        assertThat(dto.issues()).isEmpty();
        assertThatThrownBy(() -> dto.issues().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void signatureReportSnapshotsItsChainAndReasons() {
        List<CertificateInfoDto> chain = new ArrayList<>();
        List<String> reasons = new ArrayList<>(List.of("CHAIN_EXPIRED"));
        SignatureReportDto dto = new SignatureReportDto("f", "sf", null, "INTACT", null, null,
                chain, "TRUSTED", null, null, "VALID", reasons);

        chain.add(null);
        reasons.clear();

        assertThat(dto.chain()).isEmpty();
        assertThat(dto.verdictReasons()).containsExactly("CHAIN_EXPIRED");
        assertThatThrownBy(() -> dto.chain().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> dto.verdictReasons().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void analysisReportSnapshotsItsSignaturesAndSectionErrors() {
        List<SignatureReportDto> signatures = new ArrayList<>();
        List<SectionErrorDto> errors = new ArrayList<>();
        PdfAnalysisReportDto dto = new PdfAnalysisReportDto("n", 1L, null, null, null, null,
                signatures, null, errors, "NO_SIGNATURES", false);

        signatures.add(null);
        errors.add(null);

        assertThat(dto.signatures()).isEmpty();
        assertThat(dto.sectionErrors()).isEmpty();
        assertThatThrownBy(() -> dto.signatures().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> dto.sectionErrors().clear()).isInstanceOf(UnsupportedOperationException.class);
    }
}
