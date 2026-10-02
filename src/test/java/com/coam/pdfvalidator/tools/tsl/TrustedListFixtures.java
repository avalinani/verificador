package com.coam.pdfvalidator.tools.tsl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Builds small, self-contained ETSI TS 119 612 trusted lists (a LOTL and a
 * national TSL) and signs them like the real ones (enveloped XAdES-BES,
 * RSA-SHA512, exclusive C14N, a whole-document reference plus a reference to
 * {@code xades:SignedProperties}), so the TSL sync tool is tested fully
 * offline.
 */
final class TrustedListFixtures {

    static final String TSL_NS = "http://uri.etsi.org/02231/v2#";
    static final String ADDITIONAL_NS = "http://uri.etsi.org/02231/v2/additionaltypes#";
    static final String ECC_NS = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#";
    static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";

    static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    static final String TSA_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
    static final String OCSP_QC = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC";
    static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    static final String WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    static final String EXT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/";
    static final String FOR_E_SIGNATURES = EXT + "ForeSignatures";
    static final String FOR_E_SEALS = EXT + "ForeSeals";
    static final String FOR_WEB = EXT + "ForWebSiteAuthentication";
    static final String QC_FOR_ESIG = EXT + "QCForESig";
    static final String TSL_MIME = "application/vnd.etsi.tsl+xml";

    /** A fixed "now" for every test, so certificate and list validity never depend on the machine clock. */
    static final Instant NOW = Instant.parse("2026-10-02T10:00:00Z");

    private static final AtomicLong SERIAL = new AtomicLong(1);

    private TrustedListFixtures() {
    }

    record SigningKey(PrivateKey privateKey, X509Certificate certificate) {
    }

    /** How to sign a list: the defaults reproduce the real LOTL/TSL signatures. */
    record SignOptions(String firstReferenceUri, boolean contentExcludingXpath) {
        static SignOptions standard() {
            return new SignOptions("", false);
        }
    }

    static SigningKey signingKey(String commonName) {
        return signingKey(commonName, NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(365)));
    }

    static SigningKey signingKey(String commonName, Instant notBefore, Instant notAfter) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            X500Name subject = new X500Name("CN=" + commonName + ",O=Test,C=ES");
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject, BigInteger.valueOf(SERIAL.getAndIncrement()),
                    Date.from(notBefore), Date.from(notAfter), subject, keyPair.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
            return new SigningKey(keyPair.getPrivate(), certificate);
        } catch (Exception e) {
            throw new IllegalStateException("Could not build a test certificate", e);
        }
    }

    static X509Certificate certificate(String commonName) {
        return signingKey(commonName).certificate();
    }

    static X509Certificate certificate(String commonName, Instant notAfter) {
        return signingKey(commonName, NOW.minus(Duration.ofDays(400)), notAfter).certificate();
    }

    // ---------------------------------------------------------------- XML builders

    static String pointer(String location, String territory, String mimeType, X509Certificate... certificates) {
        StringBuilder identities = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            identities.append("<ServiceDigitalIdentity><DigitalId><X509Certificate>")
                    .append(base64(certificate))
                    .append("</X509Certificate></DigitalId></ServiceDigitalIdentity>");
        }
        return "<OtherTSLPointer><ServiceDigitalIdentities>" + identities + "</ServiceDigitalIdentities>"
                + "<TSLLocation>" + location + "</TSLLocation>"
                + "<AdditionalInformation>"
                + "<OtherInformation><SchemeTerritory>" + territory + "</SchemeTerritory></OtherInformation>"
                + "<OtherInformation><ns3:MimeType>" + mimeType + "</ns3:MimeType></OtherInformation>"
                + "</AdditionalInformation></OtherTSLPointer>";
    }

    static String lotl(int sequenceNumber, Instant nextUpdate, String... pointers) {
        return list(sequenceNumber, nextUpdate, "EU",
                "<PointersToOtherTSL>" + String.join("", pointers) + "</PointersToOtherTSL>", "");
    }

    static String tsl(int sequenceNumber, Instant nextUpdate, String... providers) {
        return list(sequenceNumber, nextUpdate, "ES", "",
                "<TrustServiceProviderList>" + String.join("", providers) + "</TrustServiceProviderList>");
    }

    static String provider(String name, String... services) {
        return "<TrustServiceProvider><TSPInformation><TSPName>"
                + "<Name xml:lang=\"es\">" + name + " (es)</Name><Name xml:lang=\"en\">" + name + "</Name>"
                + "</TSPName></TSPInformation><TSPServices>" + String.join("", services)
                + "</TSPServices></TrustServiceProvider>";
    }

    /** A service whose extensions carry the given AdditionalServiceInformation URIs and ECC qualifiers. */
    static String service(String name, String type, String status, List<String> additionalInformation,
                          List<String> qualifiers, X509Certificate... certificates) {
        StringBuilder identities = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            identities.append("<DigitalId><X509Certificate>").append(base64(certificate))
                    .append("</X509Certificate></DigitalId>");
        }
        identities.append("<DigitalId><X509SubjectName>CN=ignored</X509SubjectName></DigitalId>");
        StringBuilder extensions = new StringBuilder();
        for (String uri : additionalInformation) {
            extensions.append("<Extension Critical=\"false\"><AdditionalServiceInformation><URI xml:lang=\"en\">")
                    .append(uri).append("</URI></AdditionalServiceInformation></Extension>");
        }
        if (!qualifiers.isEmpty()) {
            extensions.append("<Extension Critical=\"true\"><ecc:Qualifications><ecc:QualificationElement>"
                    + "<ecc:Qualifiers>");
            for (String qualifier : qualifiers) {
                extensions.append("<ecc:Qualifier uri=\"").append(qualifier).append("\"/>");
            }
            extensions.append("</ecc:Qualifiers></ecc:QualificationElement></ecc:Qualifications></Extension>");
        }
        String extensionBlock = extensions.isEmpty()
                ? ""
                : "<ServiceInformationExtensions>" + extensions + "</ServiceInformationExtensions>";
        return "<TSPService><ServiceInformation>"
                + "<ServiceTypeIdentifier>" + type + "</ServiceTypeIdentifier>"
                + "<ServiceName><Name xml:lang=\"en\">" + name + "</Name></ServiceName>"
                + "<ServiceDigitalIdentity>" + identities + "</ServiceDigitalIdentity>"
                + "<ServiceStatus>" + status + "</ServiceStatus>"
                + "<StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>"
                + extensionBlock
                + "</ServiceInformation>"
                // History must be ignored: a withdrawn-then-granted service is judged by its current status only.
                + "<ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>" + type
                + "</ServiceTypeIdentifier><ServiceStatus>" + WITHDRAWN + "</ServiceStatus>"
                + "<StatusStartingTime>2019-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance>"
                + "</ServiceHistory></TSPService>";
    }

    private static String list(int sequenceNumber, Instant nextUpdate, String territory, String pointers,
                               String providers) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<TrustServiceStatusList xmlns=\"" + TSL_NS + "\" xmlns:ns3=\"" + ADDITIONAL_NS
                + "\" xmlns:ecc=\"" + ECC_NS + "\" Id=\"ID0001\" TSLTag=\"http://uri.etsi.org/19612/TSLTag\">"
                + "<SchemeInformation Id=\"scheme-info\">"
                + "<TSLVersionIdentifier>6</TSLVersionIdentifier>"
                + "<TSLSequenceNumber>" + sequenceNumber + "</TSLSequenceNumber>"
                + "<SchemeTerritory>" + territory + "</SchemeTerritory>"
                + pointers
                + "<ListIssueDateTime>2026-09-24T12:04:06Z</ListIssueDateTime>"
                + "<NextUpdate><dateTime>" + nextUpdate + "</dateTime></NextUpdate>"
                + "</SchemeInformation>"
                + providers
                + "</TrustServiceStatusList>";
    }

    // ---------------------------------------------------------------- signing

    static byte[] sign(String xml, SigningKey key) {
        return sign(xml, key, SignOptions.standard());
    }

    static byte[] sign(String xml, SigningKey key, SignOptions options) {
        return sign(xml.getBytes(StandardCharsets.UTF_8), key, options);
    }

    /** Signs a list (possibly one that is already signed, to build a doubly-signed document). */
    static byte[] sign(byte[] xml, SigningKey key, SignOptions options) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            Document document = factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));

            XMLSignatureFactory signatures = XMLSignatureFactory.getInstance("DOM");
            DigestMethod sha512 = signatures.newDigestMethod(DigestMethod.SHA512, null);
            Transform exclusive = signatures.newTransform(CanonicalizationMethod.EXCLUSIVE,
                    (TransformParameterSpec) null);
            List<Transform> documentTransforms = new ArrayList<>();
            documentTransforms.add(signatures.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
            if (options.contentExcludingXpath()) {
                documentTransforms.add(signatures.newTransform(Transform.XPATH, new XPathFilterParameterSpec(
                        "not(ancestor-or-self::tsl:TrustServiceProviderList)", Map.of("tsl", TSL_NS))));
            }
            documentTransforms.add(exclusive);

            String suffix = Long.toString(SERIAL.getAndIncrement());
            Element qualifyingProperties = document.createElementNS(XADES_NS, "xades:QualifyingProperties");
            qualifyingProperties.setAttributeNS(null, "Target", "#id-" + suffix);
            Element signedProperties = document.createElementNS(XADES_NS, "xades:SignedProperties");
            signedProperties.setAttributeNS(null, "Id", "xades-id-" + suffix);
            Element signatureProperties = document.createElementNS(XADES_NS, "xades:SignedSignatureProperties");
            Element signingTime = document.createElementNS(XADES_NS, "xades:SigningTime");
            signingTime.setTextContent(NOW.toString());
            signatureProperties.appendChild(signingTime);
            signedProperties.appendChild(signatureProperties);
            qualifyingProperties.appendChild(signedProperties);

            Reference documentReference = signatures.newReference(
                    options.firstReferenceUri(), sha512, documentTransforms, null, "ref-enveloped-signature");
            Reference propertiesReference = signatures.newReference("#xades-id-" + suffix, sha512,
                    List.of(exclusive), "http://uri.etsi.org/01903#SignedProperties", null);
            SignedInfo signedInfo = signatures.newSignedInfo(
                    signatures.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                            (C14NMethodParameterSpec) null),
                    signatures.newSignatureMethod(SignatureMethod.RSA_SHA512, null),
                    List.of(documentReference, propertiesReference));
            KeyInfoFactory keyInfos = signatures.getKeyInfoFactory();
            KeyInfo keyInfo = keyInfos.newKeyInfo(List.of(keyInfos.newX509Data(List.of(key.certificate()))));
            XMLObject object = signatures.newXMLObject(
                    List.of(new DOMStructure(qualifyingProperties)), null, null, null);
            XMLSignature signature = signatures.newXMLSignature(
                    signedInfo, keyInfo, List.of(object), "id-" + suffix, null);

            DOMSignContext context = new DOMSignContext(key.privateKey(), document.getDocumentElement());
            context.setDefaultNamespacePrefix("ds");
            context.setIdAttributeNS(signedProperties, null, "Id");
            registerEveryId(document, context);
            signature.sign(context);
            return serialize(document);
        } catch (Exception e) {
            throw new IllegalStateException("Could not sign the test trusted list", e);
        }
    }

    private static void registerEveryId(Document document, DOMSignContext context) {
        NodeList elements = document.getElementsByTagNameNS("*", "*");
        for (int i = 0; i < elements.getLength(); i++) {
            Element element = (Element) elements.item(i);
            if (element.hasAttributeNS(null, "Id")) {
                context.setIdAttributeNS(element, null, "Id");
            }
        }
    }

    private static byte[] serialize(Document document) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(out));
        return out.toByteArray();
    }

    static String base64(X509Certificate certificate) {
        try {
            return java.util.Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static String sha256(X509Certificate certificate) {
        try {
            return java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Replaces the first occurrence of {@code from} in an already-signed document (a post-signature tamper). */
    static byte[] tamper(byte[] signed, String from, String to) {
        String xml = new String(signed, StandardCharsets.UTF_8);
        if (!xml.contains(from)) {
            throw new IllegalArgumentException("Nothing to tamper: " + from);
        }
        return xml.replaceFirst(java.util.regex.Pattern.quote(from), to).getBytes(StandardCharsets.UTF_8);
    }
}
