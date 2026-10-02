package com.coam.pdfvalidator.tools.tsl;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.CA_QC;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.FOR_E_SEALS;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.FOR_E_SIGNATURES;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.FOR_WEB;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.GRANTED;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.NOW;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.OCSP_QC;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.QC_FOR_ESIG;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.TSA_QTST;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.WITHDRAWN;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.certificate;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.provider;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.service;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.sha256;
import static com.coam.pdfvalidator.tools.tsl.TrustedListFixtures.tsl;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Only granted services that matter for document signatures become anchors:
 * CA/QC services usable for electronic signatures (ForeSignatures, the
 * QCForESig qualifier, or no usage restriction at all) and QTST timestamp
 * services. Seal-only or website-only CAs, withdrawn services, other service
 * types and expired certificates are left out.
 */
class AnchorSelectorTest {

    private static List<TrustService> servicesOf(String... providers) throws Exception {
        String xml = tsl(1, NOW.plus(Duration.ofDays(30)), providers);
        return TrustedList.parse(SecureXml.parse(xml.getBytes(StandardCharsets.UTF_8))).services();
    }

    private static List<String> selectedSubjects(String... providers) throws Exception {
        return AnchorSelector.select(servicesOf(providers), NOW).stream()
                .map(anchor -> anchor.certificate().getSubjectX500Principal().getName())
                .map(name -> name.replaceAll(".*CN=([^,]+).*", "$1"))
                .toList();
    }

    @Test
    void selectsGrantedSignatureCapableCaQcServicesAndGrantedQtstServices() throws Exception {
        List<String> subjects = selectedSubjects(provider("TSP",
                service("For signatures", CA_QC, GRANTED, List.of(FOR_E_SIGNATURES), List.of(),
                        certificate("signatures")),
                service("Signatures and seals", CA_QC, GRANTED, List.of(FOR_E_SIGNATURES, FOR_E_SEALS), List.of(),
                        certificate("signatures-and-seals")),
                service("Seals but QCForESig", CA_QC, GRANTED, List.of(FOR_E_SEALS), List.of(QC_FOR_ESIG),
                        certificate("qcforesig")),
                service("Unrestricted", CA_QC, GRANTED, List.of(), List.of(), certificate("unrestricted")),
                service("Timestamps", TSA_QTST, GRANTED, List.of(), List.of(), certificate("tsa"))));

        assertThat(subjects).containsExactlyInAnyOrder(
                "signatures", "signatures-and-seals", "qcforesig", "unrestricted", "tsa");
    }

    @Test
    void excludesSealOnlyWebsiteOnlyWithdrawnAndOtherServiceTypes() throws Exception {
        List<String> subjects = selectedSubjects(provider("TSP",
                service("Seals only", CA_QC, GRANTED, List.of(FOR_E_SEALS), List.of(), certificate("seals")),
                service("Websites only", CA_QC, GRANTED, List.of(FOR_WEB), List.of(), certificate("web")),
                service("Seals and websites", CA_QC, GRANTED, List.of(FOR_E_SEALS, FOR_WEB), List.of(),
                        certificate("seals-web")),
                service("Withdrawn CA", CA_QC, WITHDRAWN, List.of(FOR_E_SIGNATURES), List.of(),
                        certificate("withdrawn-ca")),
                service("Withdrawn TSA", TSA_QTST, WITHDRAWN, List.of(), List.of(), certificate("withdrawn-tsa")),
                service("OCSP", OCSP_QC, GRANTED, List.of(), List.of(), certificate("ocsp"))));

        assertThat(subjects).isEmpty();
    }

    @Test
    void excludesCertificatesThatHaveAlreadyExpired() throws Exception {
        List<String> subjects = selectedSubjects(provider("TSP",
                service("Two keys", CA_QC, GRANTED, List.of(), List.of(),
                        certificate("expired", NOW.minus(Duration.ofDays(1))),
                        certificate("current", NOW.plus(Duration.ofDays(1))))));

        assertThat(subjects).containsExactly("current");
    }

    @Test
    void deduplicatesACertificateListedUnderSeveralServices() throws Exception {
        X509Certificate shared = certificate("shared");
        List<Anchor> anchors = AnchorSelector.select(servicesOf(provider("TSP",
                service("Service B", CA_QC, GRANTED, List.of(), List.of(), shared),
                service("Service A", CA_QC, GRANTED, List.of(FOR_E_SIGNATURES), List.of(), shared))), NOW);

        assertThat(anchors).hasSize(1);
        assertThat(anchors.getFirst().sha256()).isEqualTo(sha256(shared));
        assertThat(anchors.getFirst().services()).extracting(TrustService::serviceName)
                .containsExactly("Service A", "Service B");
    }

    @Test
    void namesFilesReadablyAndStablyAndOrdersThemByName() throws Exception {
        X509Certificate zeta = certificate("zeta");
        X509Certificate alpha = certificate("alpha");
        List<Anchor> anchors = AnchorSelector.select(servicesOf(
                provider("Zeta Certificación, S.A.", service("Sellos de tiempo", TSA_QTST, GRANTED, List.of(),
                        List.of(), zeta)),
                provider("Álpha TSP", service("AC Representación (G2)", CA_QC, GRANTED, List.of(), List.of(),
                        alpha))), NOW);

        assertThat(anchors).extracting(Anchor::fileName).containsExactly(
                "alpha-tsp__ac-representacion-g2__" + sha256(alpha).substring(0, 12) + ".crt",
                "zeta-certificacion-s-a__sellos-de-tiempo__" + sha256(zeta).substring(0, 12) + ".crt");
        assertThat(anchors.getFirst().kind()).isEqualTo("CA/QC");
        assertThat(anchors.getLast().kind()).isEqualTo("TSA/QTST");
    }

    @Test
    void truncatesLongNamesToKeepPathsShort() throws Exception {
        X509Certificate certificate = certificate("long");
        List<Anchor> anchors = AnchorSelector.select(servicesOf(provider(
                "A trust service provider with a remarkably long official name",
                service("Qualified certificates for natural persons issued by a long-named CA", CA_QC, GRANTED,
                        List.of(), List.of(), certificate))), NOW);

        String fileName = anchors.getFirst().fileName();
        assertThat(fileName).matches("[a-z0-9-]{1,32}__[a-z0-9-]{1,40}__[0-9a-f]{12}\\.crt");
        assertThat(fileName).doesNotContain("-__");
    }

    @Test
    void dropsTheIssuedByBoilerplateSoTheServiceSlugNamesTheCa() throws Exception {
        X509Certificate certificate = certificate("fnmt");
        List<Anchor> anchors = AnchorSelector.select(servicesOf(provider("FNMT-RCM",
                service("Qualified certificates for individuals issued by «AC FNMT Usuarios»", CA_QC, GRANTED,
                        List.of(), List.of(), certificate))), NOW);

        assertThat(anchors.getFirst().fileName())
                .isEqualTo("fnmt-rcm__ac-fnmt-usuarios__" + sha256(certificate).substring(0, 12) + ".crt");
    }
}
