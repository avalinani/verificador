package com.coam.pdfvalidator.tools.tsl;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/** One {@code TSPService}'s current {@code ServiceInformation}, as published in a national trusted list. */
record TrustService(String providerName, String serviceName, String type, String status, Instant statusStartingTime,
                    Set<String> additionalInformationUris, Set<String> qualifiers, List<X509Certificate> certificates) {

    TrustService {
        additionalInformationUris = Set.copyOf(additionalInformationUris);
        qualifiers = Set.copyOf(qualifiers);
        certificates = List.copyOf(certificates);
    }
}
