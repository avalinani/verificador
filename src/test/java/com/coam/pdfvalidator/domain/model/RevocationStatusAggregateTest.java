package com.coam.pdfvalidator.domain.model;

import com.coam.pdfvalidator.domain.port.RevocationChecker;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** T21a: how the per-certificate results of one certification path fold into a single status. */
class RevocationStatusAggregateTest {

    private static CertificateInfo certificate(String subject) {
        return new CertificateInfo(subject, null, "CN=issuer-of-" + subject, "01",
                Instant.parse("2020-01-01T00:00:00Z"), Instant.parse("2030-01-01T00:00:00Z"),
                "SHA256withRSA", List.of(), List.of(), new byte[] {1});
    }

    private static RevocationStatus status(RevocationState state, String detail) {
        return new RevocationStatus(state, "src-" + state, detail);
    }

    @Test
    void aSingleResultIsReturnedUnchanged() {
        RevocationStatus only = status(RevocationState.UNKNOWN, "no OCSP/CRL URL available for this certificate");
        assertThat(RevocationStatus.aggregate(List.of(certificate("leaf")), List.of(only))).isSameAs(only);
    }

    @Test
    void allGoodIsGoodAndCarriesTheSignersOwnResult() {
        RevocationStatus leaf = status(RevocationState.GOOD, null);
        RevocationStatus ca = status(RevocationState.GOOD, null);
        assertThat(RevocationStatus.aggregate(List.of(certificate("leaf"), certificate("ca")), List.of(leaf, ca)))
                .isSameAs(leaf);
    }

    @Test
    void aRevokedCaIsNamedInTheDetail() {
        RevocationStatus result = RevocationStatus.aggregate(
                List.of(certificate("leaf"), certificate("ca")),
                List.of(status(RevocationState.GOOD, null), status(RevocationState.REVOKED, "revoked at T")));
        assertThat(result.state()).isEqualTo(RevocationState.REVOKED);
        assertThat(result.detail()).isEqualTo("CA certificate 'ca': revoked at T");
    }

    @Test
    void aCaResultWithoutDetailStillNamesTheCertificate() {
        RevocationStatus result = RevocationStatus.aggregate(
                List.of(certificate("leaf"), certificate("ca")),
                List.of(status(RevocationState.GOOD, null), status(RevocationState.UNKNOWN, null)));
        assertThat(result.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(result.detail()).isEqualTo("CA certificate 'ca'");
    }

    @Test
    void theFirstRevokedCertificateWinsOverEarlierInconclusiveOnes() {
        RevocationStatus result = RevocationStatus.aggregate(
                List.of(certificate("leaf"), certificate("ca1"), certificate("ca2")),
                List.of(status(RevocationState.UNKNOWN, "timeout"), status(RevocationState.REVOKED, "r1"),
                        status(RevocationState.REVOKED, "r2")));
        assertThat(result.state()).isEqualTo(RevocationState.REVOKED);
        assertThat(result.detail()).contains("ca1").contains("r1");
    }

    @Test
    void aNotCheckedResultIsInconclusiveNotGood() {
        RevocationStatus result = RevocationStatus.aggregate(
                List.of(certificate("leaf"), certificate("ca")),
                List.of(status(RevocationState.GOOD, null), status(RevocationState.NOT_CHECKED, "n/a")));
        assertThat(result.state()).isEqualTo(RevocationState.NOT_CHECKED);
    }

    @Test
    void mismatchedOrEmptyInputsAreRejected() {
        assertThatThrownBy(() -> RevocationStatus.aggregate(List.of(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RevocationStatus.aggregate(
                List.of(certificate("leaf")), List.of(status(RevocationState.GOOD, null), status(RevocationState.GOOD, null))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theDefaultCheckPathSkipsTheAnchorAndPairsEachCertificateWithItsIssuer() {
        List<String> asked = new ArrayList<>();
        RevocationChecker checker = (certificate, issuer) -> {
            asked.add(certificate.subject() + "<-" + (issuer == null ? "none" : issuer.subject()));
            return status(RevocationState.GOOD, null);
        };
        checker.checkPath(List.of(certificate("leaf"), certificate("ca"), certificate("root")));
        assertThat(asked).containsExactly("leaf<-ca", "ca<-root");
    }

    @Test
    void aPathMadeOnlyOfTheAnchorIsCheckedAsALoneCertificateWithoutIssuer() {
        List<String> asked = new ArrayList<>();
        RevocationChecker checker = (certificate, issuer) -> {
            asked.add(certificate.subject() + "<-" + (issuer == null ? "none" : issuer.subject()));
            return status(RevocationState.UNKNOWN, "issuer certificate not available");
        };
        RevocationStatus result = checker.checkPath(List.of(certificate("self-signed")));
        assertThat(asked).containsExactly("self-signed<-none");
        assertThat(result.state()).isEqualTo(RevocationState.UNKNOWN);
    }
}
