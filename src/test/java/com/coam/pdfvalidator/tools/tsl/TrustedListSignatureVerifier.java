package com.coam.pdfvalidator.tools.tsl;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Verifies the enveloped XAdES signature of a trusted list with the plain
 * JDK XML-DSig API, refusing every shape that would let unsigned content
 * through:
 * <ul>
 *   <li>exactly one {@code ds:Signature} in the whole document, a direct
 *       child of the root (enveloped);</li>
 *   <li>its first {@code Reference} is {@code URI=""} (the whole document)
 *       with only the enveloped-signature and canonicalization transforms
 *       (no XPath/XSLT filter that could drop content); every other
 *       reference is same-document ({@code #id});</li>
 *   <li>{@code KeyInfo} holds exactly one certificate, whose SHA-256 must be
 *       pinned and which must be valid now, before its key is used;</li>
 *   <li>the JDK's secure validation mode stays on.</li>
 * </ul>
 * Only the root's and {@code xades:SignedProperties}' {@code Id} attributes
 * are registered as XML IDs.
 */
final class TrustedListSignatureVerifier {

    private static final String XADES_132_NS = "http://uri.etsi.org/01903/v1.3.2#";
    private static final Set<String> WHOLE_DOCUMENT_TRANSFORMS = Set.of(
            Transform.ENVELOPED,
            CanonicalizationMethod.EXCLUSIVE,
            CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
            CanonicalizationMethod.INCLUSIVE,
            CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS);

    private TrustedListSignatureVerifier() {
    }

    /** @return the signer certificate, once everything checked out */
    static X509Certificate verify(Document document, Set<String> allowedSignerSha256, Instant now)
            throws TrustedListException {
        Element root = document.getDocumentElement();
        Element signatureElement = singleEnvelopedSignature(document, root);
        registerIds(root, signatureElement);

        PinnedSignerSelector selector = new PinnedSignerSelector(allowedSignerSha256, now);
        DOMValidateContext context = new DOMValidateContext(selector, signatureElement);
        context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
        XMLSignature signature;
        try {
            signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
        } catch (MarshalException e) {
            throw new TrustedListException("The list's ds:Signature is malformed: " + e.getMessage(), e);
        }
        checkReferences(signature.getSignedInfo().getReferences());

        boolean valid;
        try {
            valid = signature.validate(context);
        } catch (XMLSignatureException e) {
            if (selector.unpinnedSha256() != null) {
                throw new UnpinnedSignerException(selector.unpinnedSha256(), e);
            }
            throw new TrustedListException("The list's signature cannot be verified: " + describe(e), e);
        }
        if (!valid) {
            throw new TrustedListException("The list's signature is invalid (" + failures(signature, context) + ")");
        }
        return selector.selected();
    }

    private static Element singleEnvelopedSignature(Document document, Element root) throws TrustedListException {
        NodeList signatures = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (signatures.getLength() != 1) {
            throw new TrustedListException("A trusted list must carry exactly one ds:Signature, found "
                    + signatures.getLength());
        }
        Element signature = (Element) signatures.item(0);
        if (signature.getParentNode() != root) {
            throw new TrustedListException("The ds:Signature is not an enveloped child of the list's root element");
        }
        return signature;
    }

    private static void registerIds(Element root, Element signature) {
        if (root.hasAttributeNS(null, "Id")) {
            root.setIdAttributeNS(null, "Id", true);
        }
        NodeList signedProperties = signature.getElementsByTagNameNS(XADES_132_NS, "SignedProperties");
        for (int i = 0; i < signedProperties.getLength(); i++) {
            Element element = (Element) signedProperties.item(i);
            if (element.hasAttributeNS(null, "Id")) {
                element.setIdAttributeNS(null, "Id", true);
            }
        }
    }

    private static void checkReferences(List<Reference> references) throws TrustedListException {
        if (references.isEmpty() || !"".equals(references.getFirst().getURI())) {
            throw new TrustedListException(
                    "The signature's first Reference must be URI=\"\" (the whole document)");
        }
        boolean enveloped = false;
        for (Transform transform : references.getFirst().getTransforms()) {
            if (!WHOLE_DOCUMENT_TRANSFORMS.contains(transform.getAlgorithm())) {
                throw new TrustedListException("The whole-document Reference uses a transform that could exclude "
                        + "content: " + transform.getAlgorithm());
            }
            enveloped |= Transform.ENVELOPED.equals(transform.getAlgorithm());
        }
        if (!enveloped) {
            throw new TrustedListException("The whole-document Reference lacks the enveloped-signature transform");
        }
        for (Reference reference : references.subList(1, references.size())) {
            String uri = reference.getURI();
            if (uri == null || !uri.startsWith("#")) {
                throw new TrustedListException("Only same-document references are allowed, found: " + uri);
            }
        }
    }

    private static String failures(XMLSignature signature, DOMValidateContext context) {
        List<String> failures = new ArrayList<>();
        try {
            if (!signature.getSignatureValue().validate(context)) {
                failures.add("signature value");
            }
            for (Reference reference : signature.getSignedInfo().getReferences()) {
                if (!reference.validate(context)) {
                    failures.add("digest of Reference URI=\"" + reference.getURI() + "\"");
                }
            }
        } catch (XMLSignatureException e) {
            failures.add(describe(e));
        }
        return failures.isEmpty() ? "unknown reason" : String.join(", ", failures) + " does not match";
    }

    /** The key selector's own explanation when it refused the signer, else the innermost cause. */
    private static String describe(Throwable throwable) {
        Throwable cause = throwable;
        while (cause.getCause() != null && cause.getCause() != cause) {
            if (cause instanceof KeySelectorException) {
                return cause.getMessage();
            }
            cause = cause.getCause();
        }
        return cause.getMessage();
    }

    /** Hands out the KeyInfo certificate's key only once it is pinned and currently valid. */
    private static final class PinnedSignerSelector extends KeySelector {

        private final Set<String> allowedSha256;
        private final Instant now;
        private X509Certificate selected;
        private String unpinnedSha256;

        PinnedSignerSelector(Set<String> allowedSha256, Instant now) {
            this.allowedSha256 = Set.copyOf(allowedSha256);
            this.now = now;
        }

        @Override
        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
                                        XMLCryptoContext context) throws KeySelectorException {
            X509Certificate certificate = singleCertificate(keyInfo);
            String sha256 = Fingerprints.sha256(certificate);
            if (!allowedSha256.contains(sha256)) {
                unpinnedSha256 = sha256;
                throw new KeySelectorException("The signer certificate " + sha256 + " is not pinned");
            }
            try {
                certificate.checkValidity(Date.from(now));
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new KeySelectorException("The signer certificate " + sha256 + " is not valid at " + now, e);
            }
            selected = certificate;
            return certificate::getPublicKey;
        }

        private static X509Certificate singleCertificate(KeyInfo keyInfo) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("The signature has no KeyInfo");
            }
            List<X509Certificate> certificates = new ArrayList<>();
            for (XMLStructure structure : keyInfo.getContent()) {
                if (structure instanceof X509Data data) {
                    for (Object item : data.getContent()) {
                        if (item instanceof X509Certificate certificate) {
                            certificates.add(certificate);
                        }
                    }
                }
            }
            if (certificates.size() != 1) {
                throw new KeySelectorException("KeyInfo must hold exactly one signer certificate, found "
                        + certificates.size());
            }
            return certificates.getFirst();
        }

        String unpinnedSha256() {
            return unpinnedSha256;
        }

        X509Certificate selected() throws TrustedListException {
            if (selected == null) {
                throw new TrustedListException("No signer certificate was selected");
            }
            return selected;
        }
    }
}
