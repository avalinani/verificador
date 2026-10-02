package com.coam.pdfvalidator.tools.tsl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The downloaded lists are untrusted input until their signature is checked: parsing must be safe first. */
class SecureXmlTest {

    @Test
    void parsesAWellFormedNamespacedDocument() throws Exception {
        Document document = SecureXml.parse(
                "<a:root xmlns:a=\"urn:test\"><a:child>x</a:child></a:root>".getBytes(StandardCharsets.UTF_8));

        assertThat(document.getDocumentElement().getNamespaceURI()).isEqualTo("urn:test");
        assertThat(document.getDocumentElement().getLocalName()).isEqualTo("root");
    }

    @Test
    void rejectsAnyDoctypeSoInternalEntityExpansionIsImpossible() {
        String billionLaughs = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">"
                + "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol2;</lolz>";

        assertThatThrownBy(() -> SecureXml.parse(billionLaughs.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(TrustedListException.class)
                .hasMessageContaining("DOCTYPE");
    }

    @Test
    void rejectsAnExternalEntityWithoutReadingTheReferencedFile(@TempDir Path directory) throws Exception {
        Path secret = directory.resolve("secret.txt");
        Files.writeString(secret, "TOP-SECRET-CONTENT");
        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"" + secret.toUri() + "\">]>"
                + "<r>&x;</r>";

        assertThatThrownBy(() -> SecureXml.parse(xxe.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(TrustedListException.class)
                .hasMessageNotContaining("TOP-SECRET-CONTENT");
    }

    @Test
    void rejectsMalformedXml() {
        assertThatThrownBy(() -> SecureXml.parse("<unclosed>".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(TrustedListException.class);
    }
}
