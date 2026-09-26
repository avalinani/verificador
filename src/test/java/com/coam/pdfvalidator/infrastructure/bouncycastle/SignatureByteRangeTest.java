package com.coam.pdfvalidator.infrastructure.bouncycastle;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Exercises {@link SignatureByteRange} directly: it is package-private and
 * used only by {@link BcSignatureVerifier}. Building the {@code pdf} bytes
 * and the {@link PDSignature} by hand (rather than through a real,
 * PDFBox-signed fixture) is deliberate: it is the only way to make the
 * {@code /ByteRange} gap and the independently-parsed {@code /Contents}
 * disagree while keeping the {@code <}/{@code >} delimiter bytes correct --
 * in a real, PDFBox-loaded PDF the two are read from the very same physical
 * bytes and can never actually disagree, which is exactly why the older,
 * self-referential gap check (comparing the gap against a length re-derived
 * from that very gap) could never fail either.
 */
class SignatureByteRangeTest {

    @Test
    void aGapMatchingTheIndependentlyParsedContentsLengthParsesSuccessfully() throws Exception {
        // "XXXX" (4 bytes) + "<AABB>" (gap: 6 bytes, a 2-byte /Contents) + "YYYY" (4 bytes)
        byte[] pdf = "XXXX<AABB>YYYY".getBytes(StandardCharsets.US_ASCII);
        PDSignature signature = new PDSignature();
        signature.setByteRange(new int[] {0, 4, 10, 4});
        signature.setContents(new byte[] {(byte) 0xAA, (byte) 0xBB});

        SignatureByteRange parsed = SignatureByteRange.parse(pdf, signature);

        assertThat(parsed.cmsDer()).containsExactly((byte) 0xAA, (byte) 0xBB);
        assertThat(parsed.signedBytes()).hasSize(8);
    }

    @Test
    void aGapDisagreeingWithTheIndependentlyParsedContentsLengthIsRejected() {
        byte[] pdf = "XXXX<AABB>YYYY".getBytes(StandardCharsets.US_ASCII);
        PDSignature signature = new PDSignature();
        signature.setByteRange(new int[] {0, 4, 10, 4});
        // The physical gap "<AABB>" is 6 bytes wide (a 2-byte /Contents), but
        // the independently-parsed /Contents COSString here claims only 1
        // byte: /ByteRange and /Contents disagree about where the signature
        // placeholder sits, which a hostile PDF could construct.
        signature.setContents(new byte[] {(byte) 0xAA});

        assertThatIllegalArgumentException()
                .isThrownBy(() -> SignatureByteRange.parse(pdf, signature))
                .withMessageContaining("does not match");
    }
}
