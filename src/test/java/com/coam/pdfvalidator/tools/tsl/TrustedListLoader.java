package com.coam.pdfvalidator.tools.tsl;

import org.w3c.dom.Document;

import java.net.URI;
import java.time.Instant;
import java.util.Set;

/** Parse safely, verify the signature against the pinned signers, then refuse a list that is past its NextUpdate. */
final class TrustedListLoader {

    private TrustedListLoader() {
    }

    static VerifiedTrustedList load(URI source, byte[] xml, Set<String> allowedSignerSha256, Instant now)
            throws TrustedListException {
        Document document = SecureXml.parse(xml);
        var signer = TrustedListSignatureVerifier.verify(document, allowedSignerSha256, now);
        TrustedList list = TrustedList.parse(document);
        if (!list.nextUpdate().isAfter(now)) {
            throw new TrustedListException(source + " is stale: its NextUpdate " + list.nextUpdate()
                    + " is not in the future");
        }
        return new VerifiedTrustedList(source, list, signer);
    }
}
