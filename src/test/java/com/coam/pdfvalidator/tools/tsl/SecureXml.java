package com.coam.pdfvalidator.tools.tsl;

import org.w3c.dom.Document;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Parses a downloaded trusted list into a DOM without ever resolving
 * anything external: namespace-aware, any DOCTYPE rejected outright (which
 * rules out both entity expansion and XXE), no external DTDs, entities,
 * schemas or XInclude, and the JAXP secure-processing limits on.
 */
final class SecureXml {

    private static final ErrorHandler FAIL_ON_ANYTHING = new ErrorHandler() {
        @Override
        public void warning(SAXParseException exception) throws SAXException {
            throw exception;
        }

        @Override
        public void error(SAXParseException exception) throws SAXException {
            throw exception;
        }

        @Override
        public void fatalError(SAXParseException exception) throws SAXException {
            throw exception;
        }
    };

    private SecureXml() {
    }

    static Document parse(byte[] xml) throws TrustedListException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setErrorHandler(FAIL_ON_ANYTHING);
            builder.setEntityResolver((publicId, systemId) -> {
                throw new SAXException("External entities are not allowed");
            });
            return builder.parse(new ByteArrayInputStream(xml));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new TrustedListException("The trusted list is not safe, well-formed XML: " + e.getMessage(), e);
        }
    }
}
