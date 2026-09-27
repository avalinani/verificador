package com.coam.pdfvalidator.spike;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.Security;
import java.util.Collection;

/**
 * Test-scoped helper (spike only, not production code) that reads a
 * signature dictionary's /ByteRange, checks its structural integrity, and
 * verifies the detached CMS signature against the ByteRange-covered bytes.
 */
public final class SpikeSignatureChecker {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private SpikeSignatureChecker() {
    }

    /** The /ByteRange array as [start1, len1, start2, len2]. */
    public record ByteRangeInfo(int start1, int len1, int start2, int len2) {

        /** Size of the gap between the two signed ranges, i.e. the /Contents hex placeholder. */
        public int gap() {
            return start2 - (start1 + len1);
        }

        /** Offset right after the second signed range. */
        public int coveredEnd() {
            return start2 + len2;
        }
    }

    public static PDSignature firstSignature(byte[] pdf) throws IOException {
        try (PDDocument document = org.apache.pdfbox.Loader.loadPDF(pdf)) {
            return document.getSignatureDictionaries().get(0);
        }
    }

    public static ByteRangeInfo byteRangeOf(PDSignature signature) {
        int[] byteRange = signature.getByteRange();
        return new ByteRangeInfo(byteRange[0], byteRange[1], byteRange[2], byteRange[3]);
    }

    public static boolean byteRangeStartsAtZero(ByteRangeInfo info) {
        return info.start1() == 0;
    }

    /**
     * The gap between the two signed ranges must equal the hex-encoded
     * /Contents string length plus the two surrounding angle brackets
     * ({@code <...>}).
     */
    public static boolean byteRangeGapMatchesContentsHexLength(byte[] pdf, PDSignature signature, ByteRangeInfo info)
            throws IOException {
        byte[] contents = signature.getContents(pdf);
        int expectedGap = contents.length * 2 + 2;
        return info.gap() == expectedGap;
    }

    /** True only when byteRange[2] + byteRange[3] reaches the end of the given bytes. */
    public static boolean byteRangeCoversWholeFile(byte[] pdf, ByteRangeInfo info) {
        return info.coveredEnd() == pdf.length;
    }

    /**
     * Verifies the detached CMS signature: recomputes the message digest over
     * the ByteRange-covered bytes and checks it against the CMS
     * SignerInformation, then verifies the signature itself against the
     * embedded signer certificate.
     */
    public static boolean verifyCms(byte[] pdf, PDSignature signature, ByteRangeInfo info) throws IOException {
        byte[] signedContent = extractSignedContent(pdf, info);
        // /Contents is a fixed-size, zero-padded placeholder (padded up to the
        // reserved preferred signature size), so it generally contains trailing
        // zero bytes after the real CMS DER structure. Reading a single ASN.1
        // object (rather than CMSSignedData(byte[]), which requires the whole
        // buffer to be consumed) tolerates that padding.
        byte[] cmsDer = signature.getContents(pdf);
        ContentInfo contentInfo = readContentInfo(cmsDer);

        try {
            CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(signedContent), contentInfo);
            Store<X509CertificateHolder> certificates = signedData.getCertificates();

            for (SignerInformation signerInformation : signedData.getSignerInfos().getSigners()) {
                Collection<X509CertificateHolder> matches = certificates.getMatches(signerInformation.getSID());
                if (matches.isEmpty()) {
                    return false;
                }
                SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(matches.iterator().next());
                if (!signerInformation.verify(verifier)) {
                    return false;
                }
            }
            return true;
        } catch (CMSException e) {
            // Includes CMSSignerDigestMismatchException: the ByteRange-covered
            // bytes no longer match the signed message digest (tampering).
            return false;
        } catch (Exception e) {
            throw new IOException("Failed to verify CMS signature", e);
        }
    }

    private static ContentInfo readContentInfo(byte[] cmsDer) throws IOException {
        try (ASN1InputStream asn1In = new ASN1InputStream(cmsDer)) {
            ASN1Primitive object = asn1In.readObject();
            return ContentInfo.getInstance(object);
        }
    }

    private static byte[] extractSignedContent(byte[] pdf, ByteRangeInfo info) {
        byte[] result = new byte[info.len1() + info.len2()];
        System.arraycopy(pdf, info.start1(), result, 0, info.len1());
        System.arraycopy(pdf, info.start2(), result, info.len1(), info.len2());
        return result;
    }
}
