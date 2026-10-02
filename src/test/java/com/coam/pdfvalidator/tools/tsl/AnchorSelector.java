package com.coam.pdfvalidator.tools.tsl;

import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Chooses which services of the national list become trust anchors (see
 * {@link #isSelected}), drops certificates that have already expired,
 * deduplicates by SHA-256 and names each file
 * {@code <tsp-slug>__<service-slug>__<sha256-prefix>.crt}, in a stable
 * order, so an unchanged list always yields the same files.
 */
final class AnchorSelector {

    static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    static final String TSA_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
    static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    private static final String EXTENSION = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/";
    static final String FOR_E_SIGNATURES = EXTENSION + "ForeSignatures";
    static final String FOR_E_SEALS = EXTENSION + "ForeSeals";
    static final String FOR_WEB_SITE_AUTHENTICATION = EXTENSION + "ForWebSiteAuthentication";
    static final String QC_FOR_ESIG = EXTENSION + "QCForESig";

    private static final Set<String> USAGE_RESTRICTIONS =
            Set.of(FOR_E_SIGNATURES, FOR_E_SEALS, FOR_WEB_SITE_AUTHENTICATION);
    private static final int PROVIDER_SLUG_LENGTH = 32;
    private static final int SERVICE_SLUG_LENGTH = 40;
    private static final String ISSUED_BY = "issued-by-";
    private static final int SHA256_PREFIX_LENGTH = 12;

    private AnchorSelector() {
    }

    /**
     * Granted (current status only) and either a QTST timestamp service, or a
     * CA/QC service usable for electronic signatures: flagged ForeSignatures,
     * qualified QCForESig, or carrying no usage restriction at all. A CA/QC
     * restricted to seals and/or website authentication is left out.
     */
    static boolean isSelected(TrustService service) {
        if (!GRANTED.equals(service.status())) {
            return false;
        }
        if (TSA_QTST.equals(service.type())) {
            return true;
        }
        if (!CA_QC.equals(service.type())) {
            return false;
        }
        Set<String> usage = new HashSet<>(service.additionalInformationUris());
        usage.retainAll(USAGE_RESTRICTIONS);
        return usage.isEmpty() || usage.contains(FOR_E_SIGNATURES) || service.qualifiers().contains(QC_FOR_ESIG);
    }

    static List<Anchor> select(List<TrustService> services, Instant now) throws TrustedListException {
        List<TrustService> selected = services.stream()
                .filter(AnchorSelector::isSelected)
                .sorted(Comparator.comparing(TrustService::providerName)
                        .thenComparing(TrustService::serviceName)
                        .thenComparing(TrustService::type))
                .toList();

        Map<String, X509Certificate> certificates = new LinkedHashMap<>();
        Map<String, List<TrustService>> servicesBySha256 = new LinkedHashMap<>();
        for (TrustService service : selected) {
            for (X509Certificate certificate : service.certificates()) {
                if (certificate.getNotAfter().toInstant().isAfter(now)) {
                    String sha256 = Fingerprints.sha256(certificate);
                    certificates.putIfAbsent(sha256, certificate);
                    List<TrustService> listing = servicesBySha256.computeIfAbsent(sha256, key -> new ArrayList<>());
                    if (!listing.contains(service)) {
                        listing.add(service);
                    }
                }
            }
        }

        List<Anchor> anchors = new ArrayList<>();
        Set<String> fileNames = new HashSet<>();
        for (Map.Entry<String, List<TrustService>> entry : servicesBySha256.entrySet()) {
            String sha256 = entry.getKey();
            TrustService naming = entry.getValue().getFirst();
            String fileName = slug(naming.providerName(), PROVIDER_SLUG_LENGTH) + "__"
                    + serviceSlug(naming.serviceName()) + "__"
                    + sha256.substring(0, SHA256_PREFIX_LENGTH) + ".crt";
            if (!fileNames.add(fileName)) {
                throw new TrustedListException("Two anchors would share the file name " + fileName);
            }
            anchors.add(new Anchor(fileName, sha256, certificates.get(sha256), entry.getValue()));
        }
        anchors.sort(Comparator.comparing(Anchor::fileName));
        return List.copyOf(anchors);
    }

    /**
     * Most service names read "Qualified certificates ... issued by &lt;CA&gt;":
     * keep only the CA part, which is what tells the files apart.
     */
    private static String serviceSlug(String serviceName) {
        String slug = slug(serviceName, Integer.MAX_VALUE);
        int issuedBy = slug.indexOf(ISSUED_BY);
        if (issuedBy >= 0 && issuedBy + ISSUED_BY.length() < slug.length()) {
            slug = slug.substring(issuedBy + ISSUED_BY.length());
        }
        return slug(slug.startsWith("the-") ? slug.substring(4) : slug, SERVICE_SLUG_LENGTH);
    }

    /** ASCII, lower case, dashes for anything else, at most {@code maxLength} characters. */
    static String slug(String name, int maxLength) {
        String ascii = Normalizer.normalize(name, Normalizer.Form.NFD).replaceAll("\\p{M}", "");
        String slug = ascii.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-+)|(-+$)", "");
        if (slug.length() > maxLength) {
            slug = slug.substring(0, maxLength).replaceAll("-+$", "");
        }
        return slug.isEmpty() ? "unnamed" : slug;
    }
}
