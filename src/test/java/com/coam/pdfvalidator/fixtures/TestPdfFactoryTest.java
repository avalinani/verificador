package com.coam.pdfvalidator.fixtures;

import com.coam.pdfvalidator.spike.SpikeSignatureChecker;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Sanity tests proving each {@link TestPdfFactory} fixture actually has the
 * property its name claims, so later tasks can trust these fixtures without
 * re-verifying them.
 */
class TestPdfFactoryTest {

    @Test
    void unsignedIsAOnePageUnencryptedUnsignedPdf() throws Exception {
        byte[] pdf = TestPdfFactory.unsigned();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.getNumberOfPages()).isEqualTo(1);
            assertThat(document.isEncrypted()).isFalse();
            assertThat(document.getSignatureDictionaries()).isEmpty();
        }
    }

    @Test
    void unsignedMultiPageHasRequestedPageCount() throws Exception {
        byte[] pdf = TestPdfFactory.unsignedMultiPage(4);
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.getNumberOfPages()).isEqualTo(4);
        }
    }

    @Test
    void signedHasExactlyOneValidSignature() throws Exception {
        byte[] pdf = TestPdfFactory.signed();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.getSignatureDictionaries()).hasSize(1);
        }
        PDSignature signature = SpikeSignatureChecker.firstSignature(pdf);
        assertThat(verifies(pdf, signature)).isTrue();
    }

    @Test
    void signedThenIncrementallyModifiedIsLongerThanTheSignedByteRange() throws Exception {
        byte[] pdf = TestPdfFactory.signedThenIncrementallyModified();
        PDSignature signature = SpikeSignatureChecker.firstSignature(pdf);
        int[] byteRange = signature.getByteRange();
        int coveredEnd = byteRange[2] + byteRange[3];
        assertThat(coveredEnd).isLessThan(pdf.length);
        assertThat(verifies(pdf, signature))
                .as("original signed bytes are untouched by the incremental update")
                .isTrue();
    }

    @Test
    void signedThenTamperedFailsCmsVerification() throws Exception {
        byte[] pdf = TestPdfFactory.signedThenTampered();
        PDSignature signature = SpikeSignatureChecker.firstSignature(pdf);
        assertThat(verifies(pdf, signature)).isFalse();
    }

    @Test
    void doublySignedHasTwoSignaturesBothVerifiable() throws Exception {
        byte[] pdf = TestPdfFactory.doublySigned();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.getSignatureDictionaries()).hasSize(2);
            for (PDSignature signature : document.getSignatureDictionaries()) {
                assertThat(verifies(pdf, signature)).isTrue();
            }
        }
    }

    @Test
    void rotatedSetsRawCosRotationPerPage() throws Exception {
        byte[] pdf = TestPdfFactory.rotated(0, 90, 180, 270, -90, 450);
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.getNumberOfPages()).isEqualTo(6);
            int[] expectedRaw = {0, 90, 180, 270, -90, 450};
            for (int i = 0; i < expectedRaw.length; i++) {
                PDPage page = document.getPage(i);
                assertThat(page.getCOSObject().getInt(COSName.ROTATE)).isEqualTo(expectedRaw[i]);
            }
        }
    }

    @Test
    void landscapeHasMediaBoxWiderThanTall() throws Exception {
        byte[] pdf = TestPdfFactory.landscape();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            PDPage page = document.getPage(0);
            assertThat(page.getMediaBox().getWidth()).isGreaterThan(page.getMediaBox().getHeight());
        }
    }

    @Test
    void withCropBoxHasACropBoxDistinctFromMediaBox() throws Exception {
        byte[] pdf = TestPdfFactory.withCropBox();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            PDPage page = document.getPage(0);
            assertThat(page.getCOSObject().containsKey(COSName.CROP_BOX)).isTrue();
            assertThat(page.getCropBox().getWidth()).isLessThan(page.getMediaBox().getWidth());
        }
    }

    @Test
    void encryptedRefusesPrintAndExtractButOpensWithOwnerPassword() throws Exception {
        byte[] pdf = TestPdfFactory.encrypted("owner-secret", "user-secret");
        try (PDDocument document = Loader.loadPDF(pdf, "owner-secret")) {
            assertThat(document.isEncrypted()).isTrue();
        }
        try (PDDocument document = Loader.loadPDF(pdf, "user-secret")) {
            assertThat(document.isEncrypted()).isTrue();
            assertThat(document.getCurrentAccessPermission().canPrint()).isFalse();
            assertThat(document.getCurrentAccessPermission().canExtractContent()).isFalse();
        }
        assertThatThrownBy(() -> Loader.loadPDF(pdf, "wrong-password")).isInstanceOf(IOException.class);
    }

    @Test
    void encryptedWithEmptyUserPasswordOpensWithoutAPasswordButIsRestricted() throws Exception {
        byte[] pdf = TestPdfFactory.encryptedWithEmptyUserPassword();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.isEncrypted()).isTrue();
            assertThat(document.getCurrentAccessPermission().canPrint()).isFalse();
        }
    }

    @Test
    void corruptStartsWithPdfHeaderButFailsToLoad() throws IOException {
        byte[] pdf = TestPdfFactory.corrupt();
        assertThat(new String(pdf, 0, 5, java.nio.charset.StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
        assertThatThrownBy(() -> Loader.loadPDF(pdf)).isInstanceOf(IOException.class);
    }

    @Test
    void notAPdfIsNotAPdfAtAll() {
        byte[] bytes = TestPdfFactory.notAPdf();
        assertThatThrownBy(() -> Loader.loadPDF(bytes)).isInstanceOf(IOException.class);
    }

    /** Reuses the spike's CMS verification logic instead of duplicating it. */
    private static boolean verifies(byte[] pdf, PDSignature signature) throws IOException {
        SpikeSignatureChecker.ByteRangeInfo byteRange = SpikeSignatureChecker.byteRangeOf(signature);
        return SpikeSignatureChecker.verifyCms(pdf, signature, byteRange);
    }
}
