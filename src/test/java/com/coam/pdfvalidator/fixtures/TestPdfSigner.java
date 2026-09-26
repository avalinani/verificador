package com.coam.pdfvalidator.fixtures;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

/**
 * Test-only helper that creates a minimal one-page PDF with PDFBox and signs
 * it with a detached CAdES (CMS) signature built with Bouncy Castle. Mirrors
 * the mechanics that a future production signer would use, but stays in the
 * test sources on purpose: this is a spike, not the real implementation.
 */
public final class TestPdfSigner {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestPdfSigner() {
    }

    public static byte[] createSimplePdf() throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                contentStream.beginText();
                contentStream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                contentStream.newLineAtOffset(100, 700);
                contentStream.showText("Signature spike test document");
                contentStream.endText();
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    public static byte[] sign(byte[] unsignedPdf, TestPki.IssuedIdentity identity) throws IOException {
        return sign(unsignedPdf, identity, PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName());
    }

    /**
     * Same as {@link #sign(byte[], TestPki.IssuedIdentity)}, but with an
     * arbitrary {@code /SubFilter} name (e.g. an unsupported or unrecognized
     * one). The CMS content itself is unaffected by this value; it only
     * changes what the signature dictionary declares.
     */
    public static byte[] sign(byte[] unsignedPdf, TestPki.IssuedIdentity identity, String subFilter)
            throws IOException {
        try (PDDocument document = org.apache.pdfbox.Loader.loadPDF(unsignedPdf)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(COSName.getPDFName(subFilter));
            signature.setName(identity.endEntityCertificate().getSubjectX500Principal().getName());
            signature.setReason("Signature spike test");
            signature.setSignDate(Calendar.getInstance());

            SignatureOptions signatureOptions = new SignatureOptions();
            signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

            SignatureInterface signatureInterface = content -> createDetachedCms(content, identity);

            document.addSignature(signature, signatureInterface, signatureOptions);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    /** Loads an already-signed PDF and adds a further incremental update (document info change). */
    public static byte[] applyIncrementalUpdate(byte[] signedPdf) throws IOException {
        try (PDDocument document = org.apache.pdfbox.Loader.loadPDF(signedPdf)) {
            document.getDocumentInformation().setTitle("Modified after signing");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    private static byte[] createDetachedCms(InputStream content, TestPki.IssuedIdentity identity)
            throws IOException {
        try {
            byte[] contentBytes = content.readAllBytes();

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            PrivateKey privateKey = identity.endEntityPrivateKey();
            X509Certificate signerCertificate = identity.endEntityCertificate();

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);

            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder()
                                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                    .build())
                            .build(contentSigner, signerCertificate));

            List<X509Certificate> chain = identity.chain();
            generator.addCertificates(new JcaCertStore(chain));

            CMSTypedData cmsData = new CMSProcessableByteArray(contentBytes);
            CMSSignedData signedData = generator.generate(cmsData, false);

            return signedData.getEncoded();
        } catch (CMSException | OperatorCreationException | CertificateEncodingException e) {
            throw new IOException("Failed to build detached CMS signature", e);
        }
    }
}
