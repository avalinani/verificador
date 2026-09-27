package com.coam.pdfvalidator.fixtures;

import org.apache.pdfbox.Loader;
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
 * Small, fixtures-local CMS verification helper used only by
 * {@link TestPdfFactoryTest} to prove a fixture's signature actually
 * verifies (or fails to). Kept independent of the {@code spike} package,
 * which is historical evidence and must not be a dependency of the fixture
 * test suite.
 */
final class FixtureCmsVerifier {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private FixtureCmsVerifier() {
    }

    static PDSignature firstSignature(byte[] pdf) throws IOException {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            return document.getSignatureDictionaries().get(0);
        }
    }

    /** Recomputes the ByteRange-covered digest and verifies the detached CMS signature against it. */
    static boolean verifies(byte[] pdf, PDSignature signature) throws IOException {
        int[] byteRange = signature.getByteRange();
        int start1 = byteRange[0];
        int len1 = byteRange[1];
        int start2 = byteRange[2];
        int len2 = byteRange[3];

        byte[] signedContent = new byte[len1 + len2];
        System.arraycopy(pdf, start1, signedContent, 0, len1);
        System.arraycopy(pdf, start2, signedContent, len1, len2);

        byte[] cmsDer = signature.getContents(pdf);
        ContentInfo contentInfo;
        try (ASN1InputStream asn1In = new ASN1InputStream(cmsDer)) {
            contentInfo = ContentInfo.getInstance(asn1In.readObject());
        }

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
            return false;
        } catch (Exception e) {
            throw new IOException("Failed to verify CMS signature", e);
        }
    }
}
