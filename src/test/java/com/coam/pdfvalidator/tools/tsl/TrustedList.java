package com.coam.pdfvalidator.tools.tsl;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The parts of an ETSI TS 119 612 trusted list (a LOTL or a national TSL)
 * that the sync needs: its scheme information, its pointers to other lists
 * and its services' CURRENT information ({@code ServiceHistory} is ignored
 * on purpose). Only {@code X509Certificate} digital identities are read.
 */
record TrustedList(int sequenceNumber, Instant issueDate, Instant nextUpdate, String territory,
                   List<TrustedListPointer> pointers, List<TrustService> services) {

    static final String TSL_NS = "http://uri.etsi.org/02231/v2#";
    static final String ADDITIONAL_TYPES_NS = "http://uri.etsi.org/02231/v2/additionaltypes#";
    static final String ECC_NS = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#";

    TrustedList {
        pointers = List.copyOf(pointers);
        services = List.copyOf(services);
    }

    static TrustedList parse(Document document) throws TrustedListException {
        Element root = document.getDocumentElement();
        if (!TSL_NS.equals(root.getNamespaceURI()) || !"TrustServiceStatusList".equals(root.getLocalName())) {
            throw new TrustedListException("Not an ETSI trusted list: unexpected root element " + root.getTagName());
        }
        Element scheme = required(root, "SchemeInformation");
        int sequenceNumber;
        try {
            sequenceNumber = Integer.parseInt(requiredText(scheme, "TSLSequenceNumber"));
        } catch (NumberFormatException e) {
            throw new TrustedListException("Invalid TSLSequenceNumber", e);
        }
        Instant issueDate = instant(requiredText(scheme, "ListIssueDateTime"));
        Instant nextUpdate = instant(requiredText(required(scheme, "NextUpdate"), "dateTime"));
        String territory = requiredText(scheme, "SchemeTerritory");

        List<TrustedListPointer> pointers = new ArrayList<>();
        Element pointerList = child(scheme, TSL_NS, "PointersToOtherTSL");
        if (pointerList != null) {
            for (Element pointer : children(pointerList, TSL_NS, "OtherTSLPointer")) {
                pointers.add(pointer(pointer));
            }
        }

        List<TrustService> services = new ArrayList<>();
        Element providerList = child(root, TSL_NS, "TrustServiceProviderList");
        if (providerList != null) {
            for (Element provider : children(providerList, TSL_NS, "TrustServiceProvider")) {
                String providerName = localizedName(required(required(provider, "TSPInformation"), "TSPName"));
                Element serviceList = child(provider, TSL_NS, "TSPServices");
                for (Element service : serviceList == null ? List.<Element>of()
                        : children(serviceList, TSL_NS, "TSPService")) {
                    services.add(service(providerName, required(service, "ServiceInformation")));
                }
            }
        }
        return new TrustedList(sequenceNumber, issueDate, nextUpdate, territory, pointers, services);
    }

    private static TrustedListPointer pointer(Element pointer) throws TrustedListException {
        List<X509Certificate> certificates = new ArrayList<>();
        Element identities = child(pointer, TSL_NS, "ServiceDigitalIdentities");
        if (identities != null) {
            for (Element identity : children(identities, TSL_NS, "ServiceDigitalIdentity")) {
                certificates.addAll(certificates(identity));
            }
        }
        String territory = null;
        String mimeType = null;
        Element additional = child(pointer, TSL_NS, "AdditionalInformation");
        if (additional != null) {
            for (Element information : children(additional, TSL_NS, "OtherInformation")) {
                Element territoryElement = child(information, TSL_NS, "SchemeTerritory");
                if (territoryElement != null) {
                    territory = territoryElement.getTextContent().strip();
                }
                Element mimeElement = child(information, ADDITIONAL_TYPES_NS, "MimeType");
                if (mimeElement != null) {
                    mimeType = mimeElement.getTextContent().strip();
                }
            }
        }
        return new TrustedListPointer(requiredText(pointer, "TSLLocation"), territory, mimeType, certificates);
    }

    private static TrustService service(String providerName, Element information) throws TrustedListException {
        Set<String> additionalInformation = new LinkedHashSet<>();
        Set<String> qualifiers = new LinkedHashSet<>();
        Element extensions = child(information, TSL_NS, "ServiceInformationExtensions");
        if (extensions != null) {
            NodeList uris = extensions.getElementsByTagNameNS(TSL_NS, "URI");
            for (int i = 0; i < uris.getLength(); i++) {
                Node uri = uris.item(i);
                if (uri.getParentNode() instanceof Element parent
                        && "AdditionalServiceInformation".equals(parent.getLocalName())) {
                    additionalInformation.add(uri.getTextContent().strip());
                }
            }
            NodeList qualifierElements = extensions.getElementsByTagNameNS(ECC_NS, "Qualifier");
            for (int i = 0; i < qualifierElements.getLength(); i++) {
                qualifiers.add(((Element) qualifierElements.item(i)).getAttribute("uri").strip());
            }
        }
        Element identity = child(information, TSL_NS, "ServiceDigitalIdentity");
        return new TrustService(
                providerName,
                localizedName(required(information, "ServiceName")),
                requiredText(information, "ServiceTypeIdentifier"),
                requiredText(information, "ServiceStatus"),
                instant(requiredText(information, "StatusStartingTime")),
                additionalInformation,
                qualifiers,
                identity == null ? List.of() : certificates(identity));
    }

    private static List<X509Certificate> certificates(Element identity) throws TrustedListException {
        List<X509Certificate> certificates = new ArrayList<>();
        for (Element digitalId : children(identity, TSL_NS, "DigitalId")) {
            Element encoded = child(digitalId, TSL_NS, "X509Certificate");
            if (encoded != null) {
                certificates.add(certificate(encoded.getTextContent()));
            }
        }
        return certificates;
    }

    static X509Certificate certificate(String base64) throws TrustedListException {
        try {
            byte[] der = Base64.getMimeDecoder().decode(base64);
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException | IllegalArgumentException e) {
            throw new TrustedListException("A digital identity is not a valid X.509 certificate", e);
        }
    }

    /** The English name when there is one (TSPs and services are named in several languages), else the first. */
    private static String localizedName(Element names) throws TrustedListException {
        List<Element> candidates = children(names, TSL_NS, "Name");
        if (candidates.isEmpty()) {
            throw new TrustedListException("Missing Name in " + names.getLocalName());
        }
        for (Element candidate : candidates) {
            if ("en".equalsIgnoreCase(candidate.getAttributeNS(XMLConstants.XML_NS_URI, "lang"))) {
                return candidate.getTextContent().strip();
            }
        }
        return candidates.getFirst().getTextContent().strip();
    }

    private static Instant instant(String text) throws TrustedListException {
        try {
            TemporalAccessor parsed = DateTimeFormatter.ISO_DATE_TIME.parseBest(
                    text, OffsetDateTime::from, LocalDateTime::from);
            return parsed instanceof OffsetDateTime offset
                    ? offset.toInstant()
                    : ((LocalDateTime) parsed).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            throw new TrustedListException("Invalid xsd:dateTime: " + text, e);
        }
    }

    private static Element required(Element parent, String localName) throws TrustedListException {
        Element element = child(parent, TSL_NS, localName);
        if (element == null) {
            throw new TrustedListException("Missing " + localName + " in " + parent.getLocalName());
        }
        return element;
    }

    private static String requiredText(Element parent, String localName) throws TrustedListException {
        String text = required(parent, localName).getTextContent().strip();
        if (text.isEmpty()) {
            throw new TrustedListException("Empty " + localName + " in " + parent.getLocalName());
        }
        return text;
    }

    private static Element child(Element parent, String namespace, String localName) {
        List<Element> matches = children(parent, namespace, localName);
        return matches.isEmpty() ? null : matches.getFirst();
    }

    private static List<Element> children(Element parent, String namespace, String localName) {
        List<Element> matches = new ArrayList<>();
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) {
                matches.add(element);
            }
        }
        return matches;
    }
}
