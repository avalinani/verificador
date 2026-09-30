package com.coam.pdfvalidator.infrastructure.pdfbox;

import com.coam.pdfvalidator.domain.exception.EncryptedPdfException;
import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.Orientation;
import com.coam.pdfvalidator.domain.model.PageInfo;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.Permission;
import com.coam.pdfvalidator.domain.model.Rotation;
import com.coam.pdfvalidator.domain.model.SecurityInfo;
import com.coam.pdfvalidator.fixtures.TestPdfFactory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PdfBoxDocumentReaderTest {

    private final PdfBoxDocumentReader reader = new PdfBoxDocumentReader();

    @Test
    void readsHeaderAndCatalogVersion() throws Exception {
        byte[] pdf = TestPdfFactory.unsigned();

        DocumentStructure structure = reader.readStructure(pdf);

        assertThat(structure.headerVersion()).isEqualTo("1.6");
        assertThat(structure.catalogVersion()).isEqualTo("1.6");
    }

    @Test
    void aMissingHeaderIsReportedAsUnknownRatherThanAborting() throws Exception {
        byte[] pdf = TestPdfFactory.missingHeader();

        DocumentStructure structure = reader.readStructure(pdf);

        assertThat(structure.headerVersion())
                .as("PDFBox can still load a document with no recognizable %PDF- header; "
                        + "the reader must not abort just because its own regex found nothing")
                .isNull();
        assertThat(structure.pageCount()).isEqualTo(1);
    }

    @Test
    void readsThePageCount() throws Exception {
        byte[] pdf = TestPdfFactory.unsignedMultiPage(4);

        DocumentStructure structure = reader.readStructure(pdf);

        assertThat(structure.pageCount()).isEqualTo(4);
        assertThat(structure.pages()).hasSize(4);
    }

    @Test
    void readsTheFourCanonicalRotationsAndNormalizesNonCanonicalOnes() throws Exception {
        byte[] pdf = TestPdfFactory.rotated(0, 90, 180, 270, -90, 450);

        List<PageInfo> pages = reader.readStructure(pdf).pages();

        assertThat(pages.get(0).rotation()).isEqualTo(Rotation.DEG_0);
        assertThat(pages.get(1).rotation()).isEqualTo(Rotation.DEG_90);
        assertThat(pages.get(2).rotation()).isEqualTo(Rotation.DEG_180);
        assertThat(pages.get(3).rotation()).isEqualTo(Rotation.DEG_270);
        assertThat(pages.get(4).rotation()).as("-90 normalizes to 270").isEqualTo(Rotation.DEG_270);
        assertThat(pages.get(5).rotation()).as("450 normalizes to 90").isEqualTo(Rotation.DEG_90);
        assertThat(pages).allMatch(PageInfo::rotationValid);
    }

    @Test
    void anInvalidRawRotationIsFlaggedNotThrown() throws Exception {
        byte[] pdf = TestPdfFactory.rotated(45);

        DocumentStructure structure = reader.readStructure(pdf);

        PageInfo page = structure.pages().get(0);
        assertThat(page.rawRotation()).isEqualTo(45);
        assertThat(page.rotationValid()).isFalse();
        assertThat(page.rotation()).as("invalid /Rotate is treated as 0 for orientation purposes")
                .isEqualTo(Rotation.DEG_0);
    }

    @Test
    void aNonIntegralRawRotationIsFlaggedInvalidEvenWhenTruncationWouldLookLikeAMultipleOfNinety()
            throws Exception {
        byte[] pdf = TestPdfFactory.rotatedWithNonIntegerValue(90.9f);

        PageInfo page = reader.readStructure(pdf).pages().get(0);

        assertThat(page.rotationValid())
                .as("90.9 truncates to 90 (a multiple of 90), but the raw value itself is not integral")
                .isFalse();
        assertThat(page.rotation()).isEqualTo(Rotation.DEG_0);
    }

    @Test
    void anIntegralFloatRawRotationIsValid() throws Exception {
        byte[] pdf = TestPdfFactory.rotatedWithNonIntegerValue(180.0f);

        PageInfo page = reader.readStructure(pdf).pages().get(0);

        assertThat(page.rotationValid()).isTrue();
        assertThat(page.rotation()).isEqualTo(Rotation.DEG_180);
    }

    @Test
    void aNonNumericRawRotationIsFlaggedInvalid() throws Exception {
        byte[] pdf = TestPdfFactory.rotatedWithNonNumericValue();

        PageInfo page = reader.readStructure(pdf).pages().get(0);

        assertThat(page.rotationValid()).isFalse();
        assertThat(page.rotation()).isEqualTo(Rotation.DEG_0);
    }

    @Test
    void aRotationInheritedFromTheParentPagesNodeIsRead() throws Exception {
        byte[] pdf = TestPdfFactory.rotatedViaInheritedPagesNode(90);

        PageInfo page = reader.readStructure(pdf).pages().get(0);

        assertThat(page.rawRotation()).isEqualTo(90);
        assertThat(page.rotation()).isEqualTo(Rotation.DEG_90);
        assertThat(page.rotationValid()).isTrue();
    }

    @Test
    void aWideMediaBoxIsReportedLandscape() throws Exception {
        byte[] pdf = TestPdfFactory.landscape();

        PageInfo page = reader.readStructure(pdf).pages().get(0);

        assertThat(page.orientation()).isEqualTo(Orientation.LANDSCAPE);
    }

    @Test
    void aPortraitPageRotated90DegreesIsReportedLandscape() throws Exception {
        byte[] pdf = TestPdfFactory.rotated(90);

        PageInfo page = reader.readStructure(pdf).pages().get(0);

        assertThat(page.mediaBox().width()).isLessThan(page.mediaBox().height());
        assertThat(page.orientation()).isEqualTo(Orientation.LANDSCAPE);
    }

    @Test
    void aSmallerCropBoxIsReadDistinctFromTheMediaBox() throws Exception {
        byte[] pdf = TestPdfFactory.withCropBox();

        PageInfo page = reader.readStructure(pdf).pages().get(0);

        assertThat(page.cropBox().width()).isLessThan(page.mediaBox().width());
    }

    @Test
    void anEncryptedPdfWithANonEmptyUserPasswordCannotBeOpened() throws Exception {
        byte[] pdf = TestPdfFactory.encrypted("owner-secret", "user-secret");

        assertThatThrownBy(() -> reader.readStructure(pdf)).isInstanceOf(EncryptedPdfException.class);
        assertThatThrownBy(() -> reader.readSecurity(pdf)).isInstanceOf(EncryptedPdfException.class);
    }

    @Test
    void anEncryptedPdfWithAnEmptyUserPasswordOpensButReportsRestrictions() throws Exception {
        byte[] pdf = TestPdfFactory.encryptedWithEmptyUserPassword();

        SecurityInfo security = reader.readSecurity(pdf);

        assertThat(security.encrypted()).isTrue();
        assertThat(security.permissions()).doesNotContain(Permission.PRINT, Permission.EXTRACT_CONTENT);
        assertThat(security.permissions()).contains(Permission.MODIFY, Permission.ANNOTATE);
    }

    @Test
    void anUnencryptedPdfReportsAllPermissions() throws Exception {
        byte[] pdf = TestPdfFactory.unsigned();

        SecurityInfo security = reader.readSecurity(pdf);

        assertThat(security.encrypted()).isFalse();
        assertThat(security.permissions()).containsExactlyInAnyOrder(Permission.values());
    }

    @Test
    void corruptBytesRaiseInvalidPdfException() throws Exception {
        byte[] pdf = TestPdfFactory.corrupt();

        assertThatThrownBy(() -> reader.readStructure(pdf)).isInstanceOf(InvalidPdfException.class);
    }

    @Test
    void notAPdfRaisesInvalidPdfException() {
        byte[] pdf = TestPdfFactory.notAPdf();

        assertThatThrownBy(() -> reader.readStructure(pdf)).isInstanceOf(InvalidPdfException.class);
    }

    /**
     * Empirically measured (not the task plan's initial guess of 1/2):
     * {@code signed()} already contains two physical revisions because
     * {@code TestPdfSigner.sign} performs the signing itself via an
     * incremental save on top of an already fully-saved unsigned PDF
     * (creation revision + signing revision). Applying one further
     * incremental update therefore yields three, not two. See the task
     * progress notes for the raw {@code %%EOF}/{@code startxref} counts that
     * back this.
     */
    @Test
    void revisionCountReflectsTheActualNumberOfIncrementalSections() throws Exception {
        assertThat(reader.readStructure(TestPdfFactory.unsigned()).revisionCount()).isEqualTo(1);
        assertThat(reader.readStructure(TestPdfFactory.signed()).revisionCount()).isEqualTo(2);
        assertThat(reader.readStructure(TestPdfFactory.signedThenIncrementallyModified()).revisionCount())
                .isEqualTo(3);
    }

    @Test
    void readsAPresentPdfaDeclaration() throws Exception {
        byte[] pdf = TestPdfFactory.pdfaDeclared(1, "B");

        PdfaDeclaration declaration = reader.readPdfaDeclaration(pdf);

        assertThat(declaration.isDeclared()).isTrue();
        assertThat(declaration.declaredPart()).contains(1);
        assertThat(declaration.declaredConformance()).contains("B");
    }

    @Test
    void reportsNoneWhenThereIsNoPdfaDeclaration() throws Exception {
        byte[] pdf = TestPdfFactory.unsigned();

        PdfaDeclaration declaration = reader.readPdfaDeclaration(pdf);

        assertThat(declaration).isEqualTo(PdfaDeclaration.NONE);
    }

    @Test
    void reportsNoneWhenTheXmpMetadataIsMalformed() throws Exception {
        byte[] pdf = TestPdfFactory.malformedXmpMetadata();

        PdfaDeclaration declaration = reader.readPdfaDeclaration(pdf);

        assertThat(declaration).isEqualTo(PdfaDeclaration.NONE);
    }

    /** T18a: an XMP stream that is a decompression bomb must not be inflated; it reads as "no declaration". */
    @Test
    void anXmpDecompressionBombReadsAsNoPdfaDeclarationWithoutInflatingIt() throws Exception {
        byte[] pdf = TestPdfFactory.decompressionBombInMetadata(8 * 1024 * 1024);
        PdfBoxDocumentReader bounded = new PdfBoxDocumentReader(
                new DecodedSizeGuard.Limits(1024 * 1024, 64L * 1024 * 1024));

        assertThat(bounded.readPdfaDeclaration(pdf)).isEqualTo(PdfaDeclaration.NONE);
    }

    /**
     * T20: the page details used to be built for every page of the tree (and later serialized), whatever the
     * page count -- a hostile page tree with millions of leaves meant millions of PageInfo objects and DTOs.
     */
    @Test
    void pageDetailsAreCappedButTheTotalPageCountIsStillReported() throws Exception {
        PdfBoxDocumentReader capped = new PdfBoxDocumentReader(
                DecodedSizeGuard.Limits.DEFAULT, new StructureLimits(2, 1_000_000, 10_000));

        DocumentStructure structure = capped.readStructure(TestPdfFactory.unsignedMultiPage(5));

        assertThat(structure.pageCount()).isEqualTo(5);
        assertThat(structure.pages()).hasSize(2);
        assertThat(structure.pages()).extracting(PageInfo::number).containsExactly(1, 2);
        assertThat(structure.pagesTruncated()).isTrue();
    }

    @Test
    void aDocumentWithinThePageCapIsNotTruncated() throws Exception {
        PdfBoxDocumentReader capped = new PdfBoxDocumentReader(
                DecodedSizeGuard.Limits.DEFAULT, new StructureLimits(5, 1_000_000, 10_000));

        DocumentStructure structure = capped.readStructure(TestPdfFactory.unsignedMultiPage(5));

        assertThat(structure.pages()).hasSize(5);
        assertThat(structure.pagesTruncated()).isFalse();
        assertThat(structure.revisionCountLowerBound()).isFalse();
    }

    @Test
    void aRevisionCountCappedByTheMarkerLimitIsFlaggedAsALowerBound() throws Exception {
        PdfBoxDocumentReader capped = new PdfBoxDocumentReader(
                DecodedSizeGuard.Limits.DEFAULT, new StructureLimits(1000, 1, 10_000));

        DocumentStructure structure = capped.readStructure(TestPdfFactory.doublySigned());

        assertThat(structure.revisionCountLowerBound()).isTrue();
        assertThat(structure.revisionCount()).isGreaterThanOrEqualTo(1);
    }
}
