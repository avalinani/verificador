package com.coam.pdfvalidator.spike;

import com.coam.pdfvalidator.fixtures.TestPdfSigner;
import com.coam.pdfvalidator.fixtures.TestPki;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spike (T01): proves, before any Spring code, that PDFBox 3 + Bouncy Castle
 * can sign a PDF and that the signature, /ByteRange integrity and any
 * post-signature tampering/modification can be verified independently.
 */
class SignatureSpikeTest {

    @Test
    void signedPdfHasStructurallySoundByteRangeAndValidCms() throws Exception {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        byte[] signed = TestPdfSigner.sign(unsigned, identity);

        PDSignature signature = SpikeSignatureChecker.firstSignature(signed);
        SpikeSignatureChecker.ByteRangeInfo byteRange = SpikeSignatureChecker.byteRangeOf(signature);

        assertThat(SpikeSignatureChecker.byteRangeStartsAtZero(byteRange)).isTrue();
        assertThat(SpikeSignatureChecker.byteRangeGapMatchesContentsHexLength(signed, signature, byteRange))
                .as("the /Contents gap must equal the hex-encoded signature length plus the surrounding <>")
                .isTrue();
        assertThat(SpikeSignatureChecker.byteRangeCoversWholeFile(signed, byteRange))
                .as("for a freshly signed PDF, byteRange[2] + byteRange[3] must equal the file length")
                .isTrue();
        assertThat(SpikeSignatureChecker.verifyCms(signed, signature, byteRange))
                .as("CMS message digest over the ByteRange bytes must match and the signer chain must verify")
                .isTrue();
    }

    @Test
    void tamperedByteInsideSignedRangeFailsCmsVerification() throws Exception {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        byte[] signed = TestPdfSigner.sign(unsigned, identity);

        PDSignature signature = SpikeSignatureChecker.firstSignature(signed);
        SpikeSignatureChecker.ByteRangeInfo byteRange = SpikeSignatureChecker.byteRangeOf(signature);

        byte[] tampered = signed.clone();
        int tamperOffset = byteRange.start1() + 10; // inside the first signed range
        tampered[tamperOffset] = (byte) (tampered[tamperOffset] ^ 0xFF);

        assertThat(SpikeSignatureChecker.verifyCms(tampered, signature, byteRange))
                .as("flipping a byte inside the first signed range must break the CMS digest")
                .isFalse();
    }

    @Test
    void incrementalUpdateAfterSigningStillVerifiesButIsDetectedAsModified() throws Exception {
        TestPki.IssuedIdentity identity = TestPki.issueSigningIdentity();
        byte[] unsigned = TestPdfSigner.createSimplePdf();
        byte[] signed = TestPdfSigner.sign(unsigned, identity);
        byte[] modifiedAfterSigning = TestPdfSigner.applyIncrementalUpdate(signed);

        PDSignature signature = SpikeSignatureChecker.firstSignature(modifiedAfterSigning);
        SpikeSignatureChecker.ByteRangeInfo byteRange = SpikeSignatureChecker.byteRangeOf(signature);

        assertThat(SpikeSignatureChecker.verifyCms(modifiedAfterSigning, signature, byteRange))
                .as("the original signed bytes are untouched, so CMS verification must still pass")
                .isTrue();
        assertThat(SpikeSignatureChecker.byteRangeCoversWholeFile(modifiedAfterSigning, byteRange))
                .as("byteRange end must now be strictly less than the file length: content was appended after signing")
                .isFalse();
        assertThat(byteRange.coveredEnd())
                .isLessThan(modifiedAfterSigning.length);
    }
}
